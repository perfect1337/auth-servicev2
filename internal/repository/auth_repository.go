package repository

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
	"github.com/perfect1337/auth-servicev2/internal/entity"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

const (
	accessTokenDuration  = 15 * time.Minute
	RefreshTokenDuration = 20 * 24 * time.Hour    // 20 дней
	secretKey            = "your-very-secret-key" // Замените на реальный секретный ключ
)

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrInvalidPassword = errors.New("invalid password")
	ErrInvalidToken    = errors.New("invalid token")
	ErrTokenExpired    = errors.New("token expired")
)

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func generateAccessToken(user *entity.User) (string, error) {
	claims := jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(accessTokenDuration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

func generateRefreshToken(userID int) (string, time.Time, error) {
	token, err := generateRandomString(32)
	if err != nil {
		return "", time.Time{}, err
	}

	expiresAt := time.Now().Add(RefreshTokenDuration)
	return token, expiresAt, nil
}

func RegisterUser(username, email, password string) (*entity.User, error) {
	hashedPassword, err := hashPassword(password)
	if err != nil {
		return nil, err
	}

	var id int
	err = DB.QueryRow(
		`INSERT INTO users (username, email, password_hash, role) 
         VALUES ($1, $2, $3, 'user') RETURNING id`,
		username, email, hashedPassword,
	).Scan(&id)

	if err != nil {
		return nil, err
	}

	return &entity.User{
		ID:       id,
		Username: username,
		Email:    email,
		Role:     "user",
	}, nil
}

func LoginUser(login, password string) (*entity.AuthResponse, error) {
	var user entity.User
	err := DB.QueryRow(
		`SELECT id, username, email, password_hash, role 
         FROM users WHERE username = $1 OR email = $1`,
		login,
	).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Добавьте проверку хеша пароля
	if !checkPasswordHash(password, user.PasswordHash) {
		return nil, ErrInvalidPassword
	}

	// Генерация токенов
	accessToken, err := generateAccessToken(&user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, expiresAt, err := generateRefreshToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Сохранение refresh token
	_, err = DB.Exec(
		`INSERT INTO refresh_tokens (user_id, token, expires_at) 
         VALUES ($1, $2, $3)`,
		user.ID, refreshToken, expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return &entity.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}, nil
}
func RefreshTokens(refreshToken string) (*entity.AuthResponse, error) {
	var token entity.RefreshToken
	var user entity.User

	err := DB.QueryRow(
		`SELECT rt.id, rt.user_id, rt.token, rt.expires_at, rt.created_at,
                u.id, u.username, u.email, u.role
         FROM refresh_tokens rt
         JOIN users u ON rt.user_id = u.id
         WHERE rt.token = $1`,
		refreshToken,
	).Scan(
		&token.ID, &token.UserID, &token.Token, &token.ExpiresAt, &token.CreatedAt,
		&user.ID, &user.Username, &user.Email, &user.Role,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrInvalidToken
		}
		return nil, err
	}

	if time.Now().After(token.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	accessToken, err := generateAccessToken(&user)
	if err != nil {
		return nil, err
	}

	newRefreshToken, expiresAt, err := generateRefreshToken(user.ID)
	if err != nil {
		return nil, err
	}

	_, err = DB.Exec(
		`UPDATE refresh_tokens 
         SET token = $1, expires_at = $2 
         WHERE id = $3`,
		newRefreshToken, expiresAt, token.ID,
	)
	if err != nil {
		return nil, err
	}

	return &entity.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		User:         user,
	}, nil
}

func ValidateToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secretKey), nil
	})
}

func InitDB(connectionString string) error {
	var err error
	DB, err = sql.Open("postgres", connectionString)
	if err != nil {
		return fmt.Errorf("failed to open database connection: %v", err)
	}

	// Проверка соединения
	if err = DB.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	log.Println("Database connection established")
	return nil
}

// RunMigrations применяет миграции к базе данных

// Exec выполняет SQL-запросы
func Exec(query string, args ...interface{}) (sql.Result, error) {
	return DB.Exec(query, args...)
}

// DeleteUser удаляет пользователя
func DeleteUser(userID string) error {
	_, err := DB.Exec("DELETE FROM users WHERE id = $1", userID)
	return err
}
