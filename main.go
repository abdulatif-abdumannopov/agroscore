// @title Farmers Credit API
// @version 1.0
// @description Мини-сервер для обработки заявок на кредиты для фермеров с авторизацией через JWT и проверкой прав.
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
package main

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"

	"farm-server/docs"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	files "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var jwtSecret = []byte("super-secret-key")

// --- Структуры данных ---

type LoginRequest struct {
	Login    string `json:"login" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type User struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	Surname        string `json:"surname"`
	Lastname       string `json:"lastname"`
	PassportCode   string `json:"passport_code"`
	PassportNumber string `json:"passport_number"`
	Pinfl          string `json:"pinfl"`
	IsAdmin        bool   `json:"-"`
	PasswordHash   string `json:"-"` // Храним хеш, но не отдаем в JSON
}

type Farm struct {
	FID     int    `json:"fid"`
	UID     int    `json:"uid"`
	Name    string `json:"name"`
	Square  int    `json:"square"`
	Quality string `json:"quality"`
	Income  int    `json:"income"`
	Cost    int    `json:"cost"`
}

type Credit struct {
	CID         int    `json:"cid"`
	UID         int    `json:"uid"`
	FID         int    `json:"fid"`
	Amount      int    `json:"amount"`
	Balance     int    `json:"balance"`
	Duration    int    `json:"duration"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

type UserClaims struct {
	UserID  int  `json:"user_id"`
	IsAdmin bool `json:"is_admin"`
	jwt.RegisteredClaims
}

// Структура для создания новой фермы (используется только Админом)
type CreateFarmRequest struct {
	UID     int    `json:"uid" binding:"required"` // Для какого пользователя создается ферма
	Name    string `json:"name" binding:"required"`
	Square  int    `json:"square" binding:"required"`
	Quality string `json:"quality" binding:"required" example:"Good"`
	Income  int    `json:"income" binding:"required"`
	Cost    int    `json:"cost" binding:"required"`
}

// Структура для подачи заявки на кредит (используется Пользователем)
type CreateCreditRequest struct {
	FID         int    `json:"fid" binding:"required"` // К какой ферме привязан кредит
	Amount      int    `json:"amount" binding:"required"`
	Duration    int    `json:"duration" binding:"required"`
	Description string `json:"description"`
}

// Структура для изменения статуса кредита (используется только Админом)
type UpdateCreditStatusRequest struct {
	Status string `json:"status" binding:"required" example:"approved"`
}

// Структура для документации ошибок в Swagger
type ErrorResponse struct {
	Error string `json:"error" example:"Invalid credentials"`
}

// --- Хелперы для паролей ---

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// --- Инициализация БД ---
// (unchanged initDB function)
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./farm.db")
	if err != nil {
		panic(err)
	}

	// Создание таблиц
	sqlScript := `
    CREATE TABLE IF NOT EXISTS USERS(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        surname TEXT NOT NULL,
        lastname TEXT NOT NULL,
        login TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        admin BOOLEAN NOT NULL DEFAULT FALSE,
        passport_code TEXT NOT NULL,
        passport_number TEXT NOT NULL,
        pinfl TEXT NOT NULL,
        CHECK (length(passport_code) = 2),
        CHECK (passport_code GLOB '[A-Za-z][A-Za-z]'),
        CHECK (length(passport_number) = 7),
        CHECK (passport_number NOT GLOB '*[^0-9]*'),
        CHECK (length(pinfl) = 16),
        CHECK (pinfl NOT GLOB '*[^0-9]*')
    );

    CREATE TABLE IF NOT EXISTS FARMS(
        fid INTEGER PRIMARY KEY AUTOINCREMENT ,
        uid INTEGER NOT NULL ,
        name TEXT NOT NULL ,
        square INTEGER NOT NULL ,
        quality TEXT NOT NULL,
        income INTEGER NOT NULL ,
        cost INTEGER NOT NULL ,
        FOREIGN KEY (uid) REFERENCES USERS(id) ON DELETE CASCADE,
        check ( quality in ('Excellent', 'Good', 'Bad') ),
        check ( income > 0 ),
        check ( cost > 0 )
    );

    CREATE TABLE IF NOT EXISTS CREDIT(
        cid INTEGER PRIMARY KEY AUTOINCREMENT ,
        uid INTEGER NOT NULL ,
        fid INTEGER NOT NULL ,
        amount INTEGER NOT NULL ,
        balance INTEGER NOT NULL DEFAULT amount,
        duration INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'wait',
        description TEXT,
        FOREIGN KEY (uid) REFERENCES USERS(id) ON DELETE CASCADE ,
        FOREIGN KEY (fid) REFERENCES FARMS(fid) ON DELETE CASCADE ,
        check ( amount > 0 ),
        check ( status in ('wait', 'approved', 'denied') ),
        check ( duration > 0 )
    );
    PRAGMA foreign_keys = ON;
    `
	_, err = db.Exec(sqlScript)
	if err != nil {
		panic(err)
	}

	// Проверяем, есть ли пользователи
	var count int
	db.QueryRow("SELECT COUNT(*) FROM USERS").Scan(&count)
	if count == 0 {
		// Мы создаем данные программно, чтобы захешировать пароли
		type InitialUser struct {
			ID                                       int
			Name, Surname, Lastname, Login, Password string
			IsAdmin                                  bool
			PCode, PNum, Pinfl                       string
		}

		users := []InitialUser{
			{1, "Ivan", "Petrov", "Sergeevich", "ivan_admin", "pass123", true, "AB", "1234567", "1234567812345678"},
			{2, "Nikita", "Sidorov", "Alimovich", "nikita_user", "qwerty", false, "CD", "7654321", "8765432187654321"},
			{3, "Alina", "Kim", "Rasulovna", "alina_user", "hello22", false, "EF", "1112223", "1122334455667788"},
		}

		stmt, _ := db.Prepare("INSERT INTO USERS (id, name, surname, lastname, login, password, admin, passport_code, passport_number, pinfl) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
		defer stmt.Close()

		for _, u := range users {
			hash, _ := hashPassword(u.Password) // Хешируем!
			stmt.Exec(u.ID, u.Name, u.Surname, u.Lastname, u.Login, hash, u.IsAdmin, u.PCode, u.PNum, u.Pinfl)
		}

		// Вставляем фермы и кредиты обычным SQL, там нет паролей
		otherData := `
        INSERT INTO FARMS (fid, uid, name, square, quality, income, cost) VALUES
        (3, 2, 'Sunny Farm', 75, 'Good', 21000, 150000),
        (4, 2, 'River Side', 110, 'Excellent', 45000, 250000),
        (5, 3, 'Golden Hill', 60, 'Bad', 15000, 70000),
        (6, 3, 'East Orchard', 85, 'Good', 27000, 120000);

        INSERT INTO CREDIT (cid, uid, fid, amount, balance, status, description, duration) VALUES
        (3, 2, 3, 8000, 8000, 'wait', 'Seeds purchase', 12),
        (4, 2, 4, 20000, 20000, 'approved', 'Irrigation system', 12),
        (5, 3, 5, 6000, 6000, 'denied', 'Request too risky', 12),
        (6, 3, 6, 9000, 9000, 'wait', 'Soil improvement project', 12);
        `
		_, err = db.Exec(otherData)
		if err != nil {
			panic(err)
		}
	}
}

// --- Middleware ---
// (unchanged AuthMiddleware function)
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]
		claims := &UserClaims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("userID", claims.UserID)
		c.Set("isAdmin", claims.IsAdmin)
		c.Next()
	}
}

// --- Handlers ---

// 1. Login Handler
// @Summary Authenticate user
// @Description Validates login and password, returns a JWT token.
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login credentials"
// @Success 200 {object} map[string]string "Returns token: {'token': 'jwt_token_string'}"
// @Failure 401 {object} ErrorResponse "Invalid credentials"
// @Router /login [post]
func loginHandler(c *gin.Context) {
	// (loginHandler logic)
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var id int
	var isAdmin bool
	var storedHash string

	// Ищем пользователя только по логину
	err := db.QueryRow("SELECT id, admin, password FROM USERS WHERE login = ?", req.Login).Scan(&id, &isAdmin, &storedHash)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	// Сравниваем присланный пароль и хеш из БД
	if !checkPasswordHash(req.Password, storedHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, UserClaims{
		UserID:  id,
		IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// Вспомогательная функция проверки доступа
func canAccessData(c *gin.Context, targetUserID int) bool {
	currentUserID := c.GetInt("userID")
	isAdmin := c.GetBool("isAdmin")
	return isAdmin || currentUserID == targetUserID
}

// 2. Get User Data Handler
// @Summary Get user profile
// @Description Retrieves user profile data. Admins can view other users' profiles using the user_id query parameter.
// @Tags Users
// @Security ApiKeyAuth
// @Produce json
// @Param user_id query int false "Target User ID (Admin access required for others)"
// @Success 200 {object} User
// @Failure 400 {object} ErrorResponse "Invalid ID format"
// @Failure 403 {object} ErrorResponse "Access Denied"
// @Failure 404 {object} ErrorResponse "User not found"
// @Router /api/users [get]
func getUserHandler(c *gin.Context) {
	// (getUserHandler logic)
	currentUserID := c.GetInt("userID")
	isAdmin := c.GetBool("isAdmin")

	targetID := currentUserID
	queryUserID := c.Query("user_id")
	if queryUserID != "" {
		id, err := strconv.Atoi(queryUserID)
		if err == nil {
			targetID = id
		}
	}

	if !isAdmin && targetID != currentUserID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied: You can only view your own profile"})
		return
	}

	row := db.QueryRow("SELECT id, name, surname, lastname, passport_code, passport_number, pinfl FROM USERS WHERE id = ?", targetID)

	var u User
	err := row.Scan(&u.ID, &u.Name, &u.Surname, &u.Lastname, &u.PassportCode, &u.PassportNumber, &u.Pinfl)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, u)
}

// 3. Get Credits Handler
// @Summary Get credit applications
// @Description Returns a list of credit applications. If user_id is not provided, returns the current user's applications.
// @Tags Credit
// @Security ApiKeyAuth
// @Produce json
// @Param user_id query int false "Target User ID (for Admin use)"
// @Success 200 {array} Credit
// @Failure 403 {object} ErrorResponse "Access Denied"
// @Router /api/credits [get]
func getCreditsHandler(c *gin.Context) {
	// (getCreditsHandler logic)
	currentUserID := c.GetInt("userID")
	targetUserID := currentUserID

	// Если админ - может запросить ?user_id=X
	if c.GetBool("isAdmin") {
		queryUserID := c.Query("user_id")
		if queryUserID != "" {
			if id, err := strconv.Atoi(queryUserID); err == nil {
				targetUserID = id
			}
		}
	}

	if !canAccessData(c, targetUserID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	rows, err := db.Query("SELECT cid, uid, fid, amount, balance, duration, status, description FROM CREDIT WHERE uid = ?", targetUserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	defer rows.Close()

	var credits []Credit
	for rows.Next() {
		var cr Credit
		var desc sql.NullString
		if err := rows.Scan(&cr.CID, &cr.UID, &cr.FID, &cr.Amount, &cr.Balance, &cr.Duration, &cr.Status, &desc); err != nil {
			continue
		}
		if desc.Valid {
			cr.Description = desc.String
		}
		credits = append(credits, cr)
	}
	if credits == nil {
		credits = []Credit{}
	}
	c.JSON(http.StatusOK, credits)
}

// 4. Get Farms Handler
// @Summary Get farm data
// @Description Returns a list of farms. If user_id is not provided, returns the current user's farms.
// @Tags Farms
// @Security ApiKeyAuth
// @Produce json
// @Param user_id query int false "Target User ID (for Admin use)"
// @Success 200 {array} Farm
// @Failure 403 {object} ErrorResponse "Access Denied"
// @Router /api/farms [get]
func getFarmsHandler(c *gin.Context) {
	// (getFarmsHandler logic)
	currentUserID := c.GetInt("userID")
	targetUserID := currentUserID

	// Если админ - может запросить ?user_id=X
	if c.GetBool("isAdmin") {
		queryUserID := c.Query("user_id")
		if queryUserID != "" {
			if id, err := strconv.Atoi(queryUserID); err == nil {
				targetUserID = id
			}
		}
	}

	if !canAccessData(c, targetUserID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	rows, err := db.Query("SELECT fid, uid, name, square, quality, income, cost FROM FARMS WHERE uid = ?", targetUserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	defer rows.Close()

	var farms []Farm
	for rows.Next() {
		var f Farm
		if err := rows.Scan(&f.FID, &f.UID, &f.Name, &f.Square, &f.Quality, &f.Income, &f.Cost); err != nil {
			continue
		}
		farms = append(farms, f)
	}
	if farms == nil {
		farms = []Farm{}
	}
	c.JSON(http.StatusOK, farms)
}

// 5. Create Farm Handler (ИСПОЛЬЗУЕТСЯ АДМИНАМИ)
// @Summary Create a new farm
// @Description Creates a new farm and assigns it to the specified user (UID). Requires Admin privileges.
// @Tags Farms
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Param request body CreateFarmRequest true "Farm details and target User ID"
// @Success 201 {object} Farm
// @Failure 400 {object} ErrorResponse "Invalid request data"
// @Failure 403 {object} ErrorResponse "Access Denied (Not an Admin)"
// @Router /api/farms [post]
func createFarmHandler(c *gin.Context) {
	if !c.GetBool("isAdmin") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied: Only administrators can create farms"})
		return
	}

	var req CreateFarmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	// Проверка существования пользователя
	var userExists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM USERS WHERE id = ?)", req.UID).Scan(&userExists)
	if err != nil || !userExists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Target user ID (UID) not found"})
		return
	}

	res, err := db.Exec("INSERT INTO FARMS (uid, name, square, quality, income, cost) VALUES (?, ?, ?, ?, ?, ?)",
		req.UID, req.Name, req.Square, req.Quality, req.Income, req.Cost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error while creating farm"})
		return
	}

	id, _ := res.LastInsertId()
	c.JSON(http.StatusCreated, Farm{
		FID:     int(id),
		UID:     req.UID,
		Name:    req.Name,
		Square:  req.Square,
		Quality: req.Quality,
		Income:  req.Income,
		Cost:    req.Cost,
	})
}

// 6. Create Credit Handler (ИСПОЛЬЗУЕТСЯ ПОЛЬЗОВАТЕЛЯМИ)
// @Summary Create a new credit application
// @Description Allows a user to apply for a credit linked to one of their farms. Status is set to 'wait'.
// @Tags Credit
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Param request body CreateCreditRequest true "Credit application details"
// @Success 201 {object} Credit
// @Failure 400 {object} ErrorResponse "Invalid request data or farm not owned by user"
// @Failure 403 {object} ErrorResponse "Access Denied"
// @Router /api/credits [post]
func createCreditHandler(c *gin.Context) {
	currentUserID := c.GetInt("userID")

	var req CreateCreditRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	// Проверка, принадлежит ли ферма пользователю
	var farmOwnerID int
	err := db.QueryRow("SELECT uid FROM FARMS WHERE fid = ?", req.FID).Scan(&farmOwnerID)
	if err != nil || farmOwnerID != currentUserID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Farm ID (FID) not found or does not belong to the current user"})
		return
	}

	res, err := db.Exec("INSERT INTO CREDIT (uid, fid, amount, balance, duration, status, description) VALUES (?, ?, ?, ?, ?, 'wait', ?)",
		currentUserID, req.FID, req.Amount, req.Amount, req.Duration, req.Description)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error while creating credit application"})
		return
	}

	id, _ := res.LastInsertId()
	c.JSON(http.StatusCreated, Credit{
		CID:         int(id),
		UID:         currentUserID,
		FID:         req.FID,
		Amount:      req.Amount,
		Balance:     req.Amount,
		Duration:    req.Duration,
		Status:      "wait",
		Description: req.Description,
	})
}

// 7. Update Credit Status Handler (ИСПОЛЬЗУЕТСЯ АДМИНАМИ)
// @Summary Update credit application status
// @Description Allows an administrator to approve or deny a credit application. Requires Admin privileges.
// @Tags Credit
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Param cid path int true "Credit ID to update"
// @Param request body UpdateCreditStatusRequest true "New status ('approved' or 'denied')"
// @Success 200 {object} Credit
// @Failure 400 {object} ErrorResponse "Invalid credit ID or status value"
// @Failure 403 {object} ErrorResponse "Access Denied (Not an Admin)"
// @Failure 404 {object} ErrorResponse "Credit not found"
// @Router /api/credits/{cid} [patch]
func updateCreditStatusHandler(c *gin.Context) {
	// (updateCreditStatusHandler logic)
	if !c.GetBool("isAdmin") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied: Only administrators can update credit status"})
		return
	}

	cidStr := c.Param("cid")
	cid, err := strconv.Atoi(cidStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid credit ID format"})
		return
	}

	var req UpdateCreditStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	newStatus := strings.ToLower(req.Status)
	if newStatus != "approved" && newStatus != "denied" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid status value. Must be 'approved' or 'denied'"})
		return
	}

	// Обновление статуса
	res, err := db.Exec("UPDATE CREDIT SET status = ? WHERE cid = ?", newStatus, cid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error while updating status"})
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Credit ID not found"})
		return
	}

	// Возвращаем обновленный объект
	var updatedCredit Credit
	row := db.QueryRow("SELECT cid, uid, fid, amount, balance, duration, status, description FROM CREDIT WHERE cid = ?", cid)
	row.Scan(&updatedCredit.CID, &updatedCredit.UID, &updatedCredit.FID, &updatedCredit.Amount, &updatedCredit.Balance, &updatedCredit.Duration, &updatedCredit.Status, &updatedCredit.Description)

	c.JSON(http.StatusOK, updatedCredit)
}

func main() {
	initDB()
	defer db.Close()

	r := gin.Default()

	r.POST("/login", loginHandler)

	api := r.Group("/api")
	api.Use(AuthMiddleware())
	{
		api.GET("/users", getUserHandler)

		// Фермы
		api.GET("/farms", getFarmsHandler)
		api.POST("/farms", createFarmHandler) // Админ создает для любого пользователя

		// Кредиты
		api.GET("/credits", getCreditsHandler)
		api.POST("/credits", createCreditHandler)             // Пользователь создает для себя
		api.PATCH("/credits/:cid", updateCreditStatusHandler) // Админ меняет статус
	}
	docs.SwaggerInfo.BasePath = "/"
	r.GET("/swagger/*any", ginSwagger.WrapHandler(files.Handler))

	r.Run(":8080")
}
