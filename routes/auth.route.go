package routes

import (
	"github.com/frankie060392/golang-gorm-postgres/controllers"
	"github.com/frankie060392/golang-gorm-postgres/middleware"
	"github.com/gin-gonic/gin"
)

type AuthRouteController struct {
	authController controllers.AuthController
}

func NewAuthRouteController(authController controllers.AuthController) AuthRouteController {
	return AuthRouteController{authController}
}

func (rc *AuthRouteController) AuthRoute(rg *gin.RouterGroup) {
	router := rg.Group("/auth")

	router.POST("/register", rc.authController.SignUpUser)
	router.POST("/login", rc.authController.SignInUser)
	router.GET("/refresh", rc.authController.RefreshToken)
	router.GET("/logout", middleware.DeserializeUser(), rc.authController.LogoutUser)
}
