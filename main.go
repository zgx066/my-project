package main

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// 用户模型
type User struct {
	ID       uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	Username string `gorm:"unique;not null" json:"username"`
	Password string `gorm:"not null" json:"password"`
	Age      int    `json:"age"`
	Gender   string `json:"gender"`
	Phone    string `json:"phone"`
}

// JWT声明
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// 全局变量
var (
	jwtSecret = []byte("your_secret_key")
	db        *gorm.DB
	// wg        sync.WaitGroup //尝试引入sync.WaitGroup
	dbonce     sync.Once
	loginGroup singleflight.Group // 专门用于登录请求合并
	userCache  sync.Map           // 用户信息缓存
)

func main() {

	// wg.Add(1)
	//初始化数据库
	initDB()
	// go func() {
	// 	initDB()
	// 	wg.Done()
	// }()

	//声明gin框架
	r := gin.Default()

	// 允许所有来源（开发环境）
	// r.Use(cors.New(cors.Config{
	// 	AllowOrigins: []string{"*"},
	// 	AllowMethods: []string{"GET", "POST"},
	// }))
	// 添加测试路由
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})

	//用户注册
	r.POST("/register", registerHandler)

	//用户登录
	r.POST("/login", loginHandler)

	//返回用户信息
	r.GET("/user", authMiddleware(), userinfoHandler)

	//更新用户信息
	r.POST("/update", updateHandler)

	r.Run(":8080")
}

func initDB() {
	dsn := "root:123!@#abc@tcp(127.0.0.1:3306)/gorm?charset=utf8mb4&parseTime=True&loc=Local"
	var err error

	//使用sync.Once避免初始化数据库多次执行
	dbonce.Do(func() {
		db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
		//虽然也能db, err = gorm.Open(mysql.Open(dsn))，但尽量传递参数 &gorm.Config{}使用默认配置，避免编译报错
		if err != nil {
			panic("连接数据库失败")
		}
		// 自动迁移表结构：检查user表是否存在，不存在则创建，存在可能调用alter table,比如新增字段
		db.AutoMigrate(&User{})

		// 获取底层 sql.DB 并配置连接池
		sqlDB, _ := db.DB()
		sqlDB.SetMaxIdleConns(10)           // 空闲连接数
		sqlDB.SetMaxOpenConns(100)          // 最大打开连接数
		sqlDB.SetConnMaxLifetime(time.Hour) // 连接最大存活时间
	})

}

// 用户注册
func registerHandler(c *gin.Context) {
	var user User
	//解析从页面获取用户注册信息
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求有误，请重新检查"})
		return
	}
	//检查用户名是否重复
	var existsuser User
	result := db.Table("users").Where("username = ?", user.Username).Scan(&existsuser)
	if result.RowsAffected > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "当前用户名已注册，请检查后重新输入"})
		return
	}

	//密码加密
	if err := user.encryPassword(user.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码加密失败"})
		return
	}

	//创建用户
	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "用户创建失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "用户创建成功", "username": user.Username})

}

// 密码加密
func (user *User) encryPassword(password string) error {
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashPassword)
	return nil
}

// 验证密码
func (user *User) passwordCheck(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err == nil {
		return true
	} else {
		return false
	}
}

// 用户登录
func loginHandler(c *gin.Context) {

	// var loginuser User
	/*用户登录只需username+password，其他信息不需要同时避免信息泄露，因此重新定义结构体loginuser，不适用原结构体User
	 */
	var loginuser struct {

		/*后面的`json:"username" form:"username" binding:"required"`进行字段映射，
		  将json的username,password分别映射到结构体；
		  binding:"required"在数据绑定阶段进行前置验证，避免无效请求进入业务逻辑，并且进行数据验证，这两个字段必须存在
		  这里同时进行json和form映射，即同时支持json+html
		*/
		Username string `json:"username" form:"username" binding:"required"`
		Password string `json:"password" form:"password" binding:"required"`
	}

	//解析从页面获取用户查询信息
	if err := c.ShouldBindJSON(&loginuser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求有误，请重新检查"})
		return
	}

	//查询用户信息
	var user User
	loginresult := db.Table("users").Where("username = ?", loginuser.Username).Scan(&user)
	if loginresult.RowsAffected <= 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "当前用户不存在"})
		return
	}

	//验证密码
	if err := user.passwordCheck(loginuser.Password); !err {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "密码输入有误"})
		return
	}

	//生成JWT
	token, err := generateToken(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": &token})

}

// 返回用户信息
func userinfoHandler(c *gin.Context) {
	//解析从页面获取用户注册信息
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "输入有误，请重新检查"})
		return
	}

	//查询用户信息
	var user User

	/*增加singleflight合并相同用户名的请求 ，防止缓存击穿*/
	result, err, _ := loginGroup.Do(username.(string), func() (interface{}, error) {

		//先从缓存中读取
		if cached, ok := userCache.Load(username); ok {
			return cached, nil
		}

		//若缓存没有，再从数据库读取
		if err := db.Table("users").Where("username = ?", username).Scan(&user).Error; err != nil {
			return nil, err
		}

		//从数据读取信息存入缓存
		userCache.Store(username, &user)
		return &user, nil
	})

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "当前用户不存在"})
		return
	}

	//返回用户信息，密码除外
	// user = result.(*User)
	//存在类型断言问题？
	userPtr, ok := result.(*User)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部服务器错误"})
		return
	}
	user = *userPtr

	c.JSON(http.StatusOK, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"age":      user.Age,
		"gender":   user.Gender,
		"phone":    user.Phone,
	})

	// c.JSON(http.StatusOK, gin.H{
	// 	"id":       user.ID,
	// 	"username": user.Username,
	// 	"age":      user.Age,
	// 	"gender":   user.Gender,
	// 	"phone":    user.Phone,
	// })

}

// 更新用户信息
func updateHandler(c *gin.Context) {
	var user User
	//解析从页面获取用户修改信息
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求有误，请重新检查"})
		return
	}

	//检查用户名是否重复
	// result := db.Table("users").Where("username = ?", user.Username)
	// if result.RowsAffected > 0 {
	// 	c.JSON(http.StatusConflict, gin.H{"当前用户名已注册，请检查后重新输入"})
	// }

	//密码加密
	if err := user.encryPassword(user.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码加密失败"})
		return
	}

	//修改用户信息：暂不支持用户名
	// result := db.Model(&User{}).Where("userid = ?", user.ID).Updates(user)
	result := db.Model(&User{}).Where("username = ?", user.Username).Updates(user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}
	//清空缓存
	userCache.Delete(user.Username)

	// 检查是否真的更新了行
	if result.RowsAffected == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "没有找到用户或数据未变更"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "修改成功", "username": user.Username})
}

// JWT认证中间件
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// tokenString := c.GetHeader("Authorization")
		tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		tokenString = strings.TrimSpace(tokenString)
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未提供认证令牌"})
			c.Abort()
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的认证令牌"})
			c.Abort()
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}

// 生成JWT令牌
func generateToken(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Issuer:    "your-app-name",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}
