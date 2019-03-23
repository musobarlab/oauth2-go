package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	rsaConf "github.com/musobarlab/oauth2-go/config/rsa"
	appDelivery "github.com/musobarlab/oauth2-go/core/application/delivery"
	appModel "github.com/musobarlab/oauth2-go/core/application/model"
	appRepo "github.com/musobarlab/oauth2-go/core/application/repository"
	appSecurity "github.com/musobarlab/oauth2-go/core/application/security"

	userDelivery "github.com/musobarlab/oauth2-go/core/user/delivery"
	userModel "github.com/musobarlab/oauth2-go/core/user/model"
	userRepo "github.com/musobarlab/oauth2-go/core/user/repository"
	jwtGen "github.com/musobarlab/oauth2-go/core/user/token"

	"github.com/musobarlab/oauth2-go/middleware"
)

func main() {
	var (
		port int64
	)

	flag.Int64Var(&port, "p", 9000, "port to listen")

	flag.Parse()

	appDB := make(map[string]*appModel.Application)
	userDB := make(map[string]*userModel.User)

	appRepository := appRepo.NewInMemory(appDB)
	userRepository := userRepo.NewInMemory(userDB)

	accessTokenAge, err := time.ParseDuration("5m")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	privateKey, err := rsaConf.InitPrivateKey()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	publicKey, err := rsaConf.InitPublicKey()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	security := appSecurity.NewAES("orakepriwekepriw")

	accessTokenGenerator := jwtGen.NewJwtGenerator(privateKey, accessTokenAge)

	appHandler := &appDelivery.Handler{AppRepo: appRepository, UserRepo: userRepository, Security: security, AccessTokenGenerator: accessTokenGenerator}
	userHandler := &userDelivery.Handler{UserRepo: userRepository, AccessTokenGenerator: accessTokenGenerator}

	//fs := http.FileServer(http.Dir("static"))
	http.HandleFunc("/", appHandler.IndexHandler())
	http.HandleFunc("/get_register", appHandler.GetRegisterHandler())
	http.HandleFunc("/post_register", appHandler.PostRegisterHandler())
	http.HandleFunc("/get_authorize_user", appHandler.GetAuthorizeUser())
	http.HandleFunc("/list_app", appHandler.ListAppHandler())
	http.HandleFunc("/get_login", userHandler.GetLogin())
	http.HandleFunc("/post_login", userHandler.PostLogin())
	http.HandleFunc("/about", appHandler.AboutHandler())

	http.HandleFunc("/api/oauth2/token", appHandler.OAuth2Handler())

	http.HandleFunc("/api/users", userHandler.CreateUser())
	http.HandleFunc("/api/users/auth", userHandler.Auth())
	http.HandleFunc("/api/users/me", middleware.JWTVerify(publicKey, userHandler.Me()))

	log.Println("Listening...")
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}
