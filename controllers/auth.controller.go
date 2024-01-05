package controllers

import (
	"net/http"
	"strings"
	"time"

	"github.com/frankie060392/golang-gorm-postgres/models"
	"github.com/frankie060392/golang-gorm-postgres/utils"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/render"
	"gorm.io/gorm"
)

type AuthController struct {
	DB *gorm.DB
}

func NewAuthController(DB *gorm.DB) AuthController {
	return AuthController{DB}
}

func (ac *AuthController) SignupUser(ctx *gin.Context) {
	var payload *models.SignUpInput
	if err := ctx.ShouldBindJSON(payload); err != nil {
		ctx.Render(http.StatusBadRequest, render.JSON{Data: any(gin.H{"status": "failed", "message": err.Error()})})
		return
	}

	if payload.Password != payload.PasswordConfirm {
		ctx.Render(http.StatusBadRequest, render.JSON{Data: any(gin.H{"status": "failed", "message": "Password not match"})})
		return
	}

	hashedPassword, err := utils.HashPassword(payload.Password)
	if err != nil {
		ctx.Render(http.StatusBadRequest, render.JSON{Data: any(gin.H{"status": "failed", "message": "Cant hash"})})
		return
	}

	now := time.Now()
	newUser := models.User{
		Name:      payload.Name,
		Email:     strings.ToLower(payload.Email),
		Password:  hashedPassword,
		Role:      "user",
		Verified:  true,
		Photo:     payload.Photo,
		Provider:  "local",
		CreatedAt: now,
		UpdatedAt: now,
	}

	result := ac.DB.Create(newUser)

	if result.Error != nil && strings.Contains(result.Error.Error(), "duplicate key value violates unique") {
		ctx.JSON(http.StatusConflict, gin.H{"status": "fail", "message": "User with that email already exists"})
		return
	} else if result.Error != nil {
		ctx.JSON(http.StatusBadGateway, gin.H{"status": "error", "message": "Something bad happened"})
		return
	}

	userResponse := &models.UserResponse{
		ID:        newUser.ID,
		Name:      newUser.Name,
		Email:     newUser.Email,
		Photo:     newUser.Photo,
		Role:      newUser.Role,
		Provider:  newUser.Provider,
		CreatedAt: newUser.CreatedAt,
		UpdatedAt: newUser.UpdatedAt,
	}
	ctx.JSON(http.StatusCreated, gin.H{"status": "success", "data": gin.H{"user": userResponse}})

}
