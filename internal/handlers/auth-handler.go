package repository

import (
	"awesomeProject/internal/entity"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
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
func GetAllTopics() ([]entity.Post, error) { // Используйте entity.Post вместо Post
	rows, err := DB.Query(`
        SELECT p.id, p.title, p.content, p.created_at, p.author_id 
        FROM posts p
        ORDER BY p.created_at DESC
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var topics []entity.Post // Используйте entity.Post
	for rows.Next() {
		var topic entity.Post
		if err := rows.Scan(
			&topic.ID,
			&topic.Title,
			&topic.Content,
			&topic.CreatedAt,
			&topic.AuthorID,
		); err != nil {
			return nil, err
		}
		topics = append(topics, topic)
	}

	if topics == nil {
		topics = []entity.Post{} // Используйте entity.Post
	}

	return topics, nil // Убрали c.JSON, так как это ответственность handler
}

// RunMigrations применяет миграции к базе данных
func RunMigrations() error {
	driver, err := postgres.WithInstance(DB, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("could not create migration driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://C:/Users/jopa/GolandProjects/awesomeProject/internal/migrations",
		"postgres", driver)
	if err != nil {
		return fmt.Errorf("could not initialize migrator: %w", err)
	}

	// Выполняем миграции только один раз
	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("could not apply migrations: %w", err)
	}

	// Получаем версию только если миграции успешны
	version, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return fmt.Errorf("could not get migration version: %w", err)
	}

	log.Printf("Migrations applied. Current version: %d, dirty: %v", version, dirty)
	return nil
}

// Exec выполняет SQL-запросы
func Exec(query string, args ...interface{}) (sql.Result, error) {
	return DB.Exec(query, args...)
}

// GetAllUsers возвращает всех пользователей
func GetAllUsers() ([]entity.User, error) {
	rows, err := DB.Query("SELECT id, username, email, role FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []entity.User
	for rows.Next() {
		var user entity.User
		if err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.Role); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

// GetUserPosts возвращает посты пользователя
func GetUserPosts(userID string) ([]entity.Post, error) {
	rows, err := DB.Query("SELECT id, title, content, created_at FROM posts WHERE author_id = $1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []entity.Post
	for rows.Next() {
		var post entity.Post
		if err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.CreatedAt); err != nil {
			return nil, err
		}
		posts = append(posts, post)
	}
	return posts, nil
}

// AddPost добавляет новый пост
func AddPost(post *entity.Post) error {
	err := DB.QueryRow(
		"INSERT INTO posts (title, content, author_id) VALUES ($1, $2, $3) RETURNING id, created_at",
		post.Title, post.Content, post.AuthorID,
	).Scan(&post.ID, &post.CreatedAt)
	return err
}

// DeleteUser удаляет пользователя
func DeleteUser(userID string) error {
	_, err := DB.Exec("DELETE FROM users WHERE id = $1", userID)
	return err
}

// GetDBStats возвращает статистику по БД
func GetDBStats() (map[string]int, error) {
	stats := make(map[string]int)

	var userCount int
	err := DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if err != nil {
		return nil, err
	}
	stats["user_count"] = userCount

	var postCount int
	err = DB.QueryRow("SELECT COUNT(*) FROM posts").Scan(&postCount)
	if err != nil {
		return nil, err
	}
	stats["post_count"] = postCount

	return stats, nil
}
