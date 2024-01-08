package controllers

import (
	"net/http"

	"github.com/frankie060392/golang-gorm-postgres/models"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type UserController struct {
	DB *gorm.DB
}

func NewUserController(DB *gorm.DB) UserController {
	return UserController{DB}
}

func (uc *UserController) GetMe(ctx *gin.Context) {
	currentUser := ctx.MustGet("currentUser").(models.User)

	userResponse := &models.UserResponse{
		ID:        currentUser.ID,
		Name:      currentUser.Name,
		Email:     currentUser.Email,
		Photo:     currentUser.Photo,
		Role:      currentUser.Role,
		Provider:  currentUser.Provider,
		CreatedAt: currentUser.CreatedAt,
		UpdatedAt: currentUser.UpdatedAt,
	}

	ctx.JSON(http.StatusOK, models.ResponseData{Status: models.Success, Message: "Login success", Data: gin.H{"user": userResponse}})
}

func (uc *UserController) UpdateUser(ctx *gin.Context) {
	currentUser := ctx.MustGet("currentUser").(models.User)

	var payload *models.UpdateUser
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"status": "failed", "message": err.Error()})
		return
	}

	var updatedUser models.User
	result := uc.DB.First(&updatedUser, "id = ?", currentUser.ID)
	if result.Error != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"status": "failed", "message": result.Error})
	}

	userToUpdate := models.User{
		Name:  payload.Name,
		Photo: payload.Photo,
	}

	uc.DB.Model(updatedUser).Updates(userToUpdate)
	ctx.JSON(http.StatusOK, models.ResponseData{Status: models.Success, Message: "Login success", Data: userToUpdate})
}
