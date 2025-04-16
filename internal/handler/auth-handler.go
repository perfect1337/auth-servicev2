package handler

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/perfect1337/auth-servicev2/internal/repository"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type HTTPHandler struct {
	repo *repository.Repository // Adjust this according to your repository struct
}

func NewHTTPHandler(repo *repository.Repository) *HTTPHandler {
	return &HTTPHandler{repo: repo}
}
func (h *HTTPHandler) Register(c *gin.Context) {
	type RegisterRequest struct {
		Username string `json:"username" binding:"required,min=3,max=20"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check for user uniqueness
	var count int
	err := h.repo.DB.QueryRow(
		"SELECT COUNT(*) FROM users WHERE username = $1 OR email = $2",
		req.Username, req.Email,
	).Scan(&count)

	if err != nil || count > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "Username or email already exists"})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(req.Password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password hashing failed"})
		return
	}

	// Save the user
	var userID int
	err = h.repo.DB.QueryRow(
		`INSERT INTO users (username, email, password_hash) 
        VALUES (\$1, \$2, \$3) 
        RETURNING id`,
		req.Username,
		req.Email,
		string(hashedPassword),
	).Scan(&userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User  registered successfully",
		"user_id": userID,
	})
}
func (h *HTTPHandler) Login(c *gin.Context) {
	log.Println("Incoming login request")

	var input struct {
		Login    string `json:"login" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	// Log the raw request body for debugging
	body, _ := c.GetRawData()
	log.Printf("Raw request body: %s", string(body))
	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	if err := c.ShouldBindJSON(&input); err != nil {
		log.Printf("Login bind error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   err.Error(),
			"details": "Invalid request format",
		})
		return
	}

	authResponse, err := h.repo.LoginUser(input.Login, input.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	if err != nil {
		log.Printf("Ошибка входа для %s: %v", input.Login, err) // Добавьте эту строку
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные"})
		return
	}
	log.Printf("Attempting login for: %s", input.Login)
	// Set cookie with proper settings
	c.SetCookie(
		"refresh_token",
		authResponse.RefreshToken,
		int(repository.RefreshTokenDuration/time.Second),
		"/",
		"localhost", // Important: match your frontend domain
		false,       // Secure should be true in production (HTTPS only)
		true,        // HttpOnly
	)

	c.JSON(http.StatusOK, gin.H{
		"access_token": authResponse.AccessToken,
		"user":         authResponse.User,
	})
}
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
func (h *HTTPHandler) Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token required"})
		return
	}

	authResponse, err := h.repo.RefreshTokens(refreshToken) // Use h.repo here
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Обновляем refresh token в cookie
	c.SetCookie(
		"refresh_token",
		authResponse.RefreshToken,
		int(repository.RefreshTokenDuration/time.Second),
		"/",
		"localhost",
		false,
		true,
	)

	c.JSON(http.StatusOK, gin.H{
		"access_token": authResponse.AccessToken,
		"user":         authResponse.User,
	})

}

func (h *HTTPHandler) Logout(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "Already logged out"})
		return
	}

	// Удаляем refresh token из БД
	_, err = h.repo.DB.Exec( // Use h.repo.DB here
		"DELETE FROM refresh_tokens WHERE token = $1",
		refreshToken,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Удаляем cookie
	c.SetCookie(
		"refresh_token",
		"",
		-1,
		"/",
		"localhost",
		false,
		true,
	)

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}
func AuthMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		tokenString := authHeader[len("Bearer "):]
		token, err := repository.ValidateToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}
		if userRole, ok := claims["role"].(string); ok {
			if requiredRole != "" && userRole != requiredRole {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
				return
			}
		}
		// Проверяем роль пользователя
		if requiredRole != "" {
			userRole, ok := claims["role"].(string)
			if !ok || userRole != requiredRole {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
				return
			}
		}

		// Добавляем информацию о пользователе в контекст
		c.Set("userID", claims["user_id"])
		c.Set("username", claims["username"])
		c.Set("role", claims["role"])

		c.Next()
	}
}
