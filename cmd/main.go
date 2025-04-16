package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/perfect1337/auth-servicev2/internal/handler"
	"github.com/perfect1337/auth-servicev2/internal/repository"
)

func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Log the incoming request
		log.Printf("%s %s %s\n", c.Request.Method, c.Request.URL, c.Request.Proto)
		log.Println("Headers:", c.Request.Header)

		// Copy the body so we can log it
		body, _ := c.GetRawData()
		log.Println("Body:", string(body))
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(body))

		// Continue processing
		c.Next()

		// Log the response
		log.Printf("Response status: %d\n", c.Writer.Status())
	}
}
func main() {
	// Инициализация БД
	repo, err := repository.InitDB("user=postgres dbname=PG password=postgres host=localhost port=5432 sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("HTTP server started on :8080")

	// HTTP сервер
	router := gin.Default()
	router.Run(":8080")
	router.Use(RequestLogger())
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length", "Set-Cookie"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	router.GET("/debug", func(c *gin.Context) {
		refreshToken, _ := c.Cookie("refresh_token")
		c.JSON(200, gin.H{
			"cookie_received": refreshToken != "",
			"token_length":    len(refreshToken),
		})
	})
	httpHandler := handler.NewHTTPHandler(repo)

	authGroup := router.Group("/auth")
	{
		authGroup.POST("/register", httpHandler.Register)
		authGroup.POST("/login", httpHandler.Login)
		authGroup.POST("/refresh", httpHandler.Refresh)
		authGroup.POST("/logout", httpHandler.Logout)
	}

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
}
