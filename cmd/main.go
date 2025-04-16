package main

import (
	"log"
	"net"

	"github.com/gin-gonic/gin"
	"github.com/perfect1337/auth-service/internal/handler"
	"github.com/perfect1337/auth-service/internal/repository"
	"google.golang.org/grpc"
)

func main() {
	// Инициализация БД
	repo, err := repository.NewPostgresRepo("postgres://auth_user:password@auth-db:5432/auth?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	// Запуск gRPC сервера
	go func() {
		lis, err := net.Listen("tcp", ":50051")
		if err != nil {
			log.Fatal(err)
		}

		grpcServer := grpc.NewServer()
		handler.RegisterAuthServiceServer(grpcServer, handler.NewAuthHandler(repo))
		log.Println("gRPC server started on :50051")
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatal(err)
		}
	}()

	// HTTP сервер
	router := gin.Default()
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

	log.Println("HTTP server started on :8080")
	router.Run(":8080")
}
