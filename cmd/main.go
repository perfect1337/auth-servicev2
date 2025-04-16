package main

import (
	"log"
	"time"

	"github.com/perfect1337/auth-servicev2/internal/handler"
	"github.com/perfect1337/auth-servicev2/internal/repository"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// Инициализация БД
	err := repository.InitDB("postgres://postgres:postgres@localhost:5432/PG?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	// Применение миграций
	err = repository.RunMigrations()
	if err != nil {
		log.Fatal(err)
	}

	router := gin.Default()

	// Настройка CORS
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Логирование запросов
	router.Use(func(c *gin.Context) {
		log.Printf("Получен запрос: %s %s", c.Request.Method, c.Request.URL.Path)
		c.Next()
	})

	// Роуты
	router.GET("/auth/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Группа аутентификации
	auth := router.Group("/auth")
	{
		auth.POST("/register", handlers.Register)
		auth.POST("/login", handlers.Login)
		auth.POST("/refresh", handlers.Refresh)
		auth.POST("/logout", handlers.Logout)
	}

	// Защищенные роуты
	api := router.Group("/api")
	api.Use(handlers.AuthMiddleware(""))
	{
		api.GET("/users", handlers.GetAllUsers)
		api.GET("/users/:id/posts", handlers.GetUserPosts)
		api.POST("/posts", handlers.AddPost)
		api.GET("/topics", handlers.GetAllTopics)
		api.GET("/stats", handlers.GetDBStats)
	}

	// Админские роуты
	admin := router.Group("/admin")
	admin.Use(handlers.AuthMiddleware("admin"))
	{
		admin.GET("/users", handlers.AdminGetAllUsers)
		admin.DELETE("/users/:id", handlers.AdminDeleteUser)
	}

	// Запуск сервера
	log.Println("Сервер запущен на http://localhost:8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
