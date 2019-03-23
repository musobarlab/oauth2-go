package delivery

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/satori/go.uuid"

	userModel "github.com/musobarlab/oauth2-go/core/user/model"
	userRepo "github.com/musobarlab/oauth2-go/core/user/repository"
	jwtGen "github.com/musobarlab/oauth2-go/core/user/token"
)

// Handler struct
type Handler struct {
	UserRepo             userRepo.Repository
	AccessTokenGenerator jwtGen.AccessTokenGenerator
}

// GetLogin function
func (h *Handler) GetLogin() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var tmpl *template.Template

		message := struct {
			Done bool
		}{
			Done: false,
		}

		tmpl = template.Must(template.ParseFiles("./static/login_user.html"))
		tmpl.Execute(res, message)

	}

}

// PostLogin function
func (h *Handler) PostLogin() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var tmpl *template.Template

		message := struct {
			Done    bool
			Message string
		}{
			Message: "invalid method",
		}

		if req.Method != http.MethodPost {
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			tmpl.Execute(res, message)
			return
		}

		email := req.FormValue("email")
		password := req.FormValue("password")

		if len(email) <= 0 {
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			message.Message = "email is required"

			tmpl.Execute(res, message)
			return
		}

		if len(password) <= 0 {
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			message.Message = "password is required"

			tmpl.Execute(res, message)
			return
		}

		output := h.UserRepo.FindByEmail(email)
		if output.Error != nil {
			res.WriteHeader(401)
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			message.Message = "invalid email or password"
			tmpl.Execute(res, message)
			return
		}

		userRes := output.Result.(*userModel.User)
		if !userRes.IsValidPassword(password) {
			res.WriteHeader(401)
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			message.Message = "invalid email or password"
			tmpl.Execute(res, message)
			return
		}

		// set cookie

		http.SetCookie(res, &http.Cookie{
			Name:    "user_id",
			Value:   userRes.ID,
			Expires: time.Now().Add(10 * time.Minute),
		})

		tmpl = template.Must(template.ParseFiles("./static/index.html"))
		res.WriteHeader(200)
		message.Message = "Login success"
		tmpl.Execute(res, message)

	}
}

// CreateUser function
func (h *Handler) CreateUser() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {

		if req.Method != http.MethodPost {
			res.Header().Add("Content-Type", "application/json")
			res.WriteHeader(400)
			res.Write([]byte(`{"success": false, "code": 400, "message": "invalid method"}`))
			return
		}

		var user userModel.User
		if err := json.NewDecoder(req.Body).Decode(&user); err != nil {
			res.Header().Add("Content-Type", "application/json")
			res.WriteHeader(400)
			res.Write([]byte(`{"success": false, "code": 400, "message": "invalid payload"}`))
			return
		}

		user.ID = uuid.NewV4().String()

		output := h.UserRepo.Save(&user)
		if output.Error != nil {
			res.Header().Add("Content-Type", "application/json")
			res.WriteHeader(400)
			res.Write([]byte(`{"success": false, "code": 400, "message": "error create user"}`))
			return
		}

		payload, _ := json.Marshal(user)

		res.Header().Add("Content-Type", "application/json")
		res.WriteHeader(201)
		res.Write(payload)
	}
}

// Me function
func (h *Handler) Me() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		userID := req.Header.Get("userId")

		output := h.UserRepo.FindByID(userID)
		if output.Error != nil {
			res.Header().Add("Content-Type", "application/json")
			res.WriteHeader(400)
			res.Write([]byte(`{"success": false, "code": 400, "message": "user not found"}`))
			return
		}

		userRes := output.Result.(*userModel.User)

		userPayload := struct {
			Success bool        `json:"success"`
			Code    string      `json:"code"`
			Message string      `json:"message"`
			Data    interface{} `json:"data"`
		}{
			Success: true,
			Code:    "200",
			Message: "get me",
			Data:    userRes,
		}

		payload, _ := json.Marshal(userPayload)
		res.Header().Add("Content-Type", "application/json")
		res.WriteHeader(200)
		res.Write(payload)
	}
}

// Auth function
func (h *Handler) Auth() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var user userModel.User
		if err := json.NewDecoder(req.Body).Decode(&user); err != nil {
			res.Header().Add("Content-Type", "application/json")
			res.WriteHeader(400)
			res.Write([]byte(`{"success": false, "code": 400, "message": "invalid payload"}`))
			return
		}

		output := h.UserRepo.FindByEmail(user.Email)
		if output.Error != nil {
			res.Header().Add("Content-Type", "application/json")
			res.WriteHeader(401)
			res.Write([]byte(`{"success": false, "code": 401, "message": "invalid username or password"}`))
			return
		}

		userRes := output.Result.(*userModel.User)
		if !userRes.IsValidPassword(user.Password) {
			res.Header().Add("Content-Type", "application/json")
			res.WriteHeader(401)
			res.Write([]byte(`{"success": false, "code": 401, "message": "invalid username or password"}`))
			return
		}

		claim := jwtGen.Claim{
			Issuer:   "wuriyanto.com",
			Audience: userRes.ID,
			Subject:  userRes.ID,
			Email:    userRes.Email,
		}

		tokenResult := <-h.AccessTokenGenerator.GenerateAccessToken(claim)
		if tokenResult.Error != nil {
			res.Header().Add("Content-Type", "application/json")
			res.WriteHeader(401)
			res.Write([]byte(`{"success": false, "code": 401, "message": "invalid username or password"}`))
			return
		}

		accessToken := tokenResult.AccessToken

		res.Header().Add("Content-Type", "application/json")
		res.WriteHeader(200)
		res.Write([]byte(fmt.Sprintf(`{"success": false, "code": 200, "message": "user login", "data": "%s"}`, fmt.Sprintf("Bearer %s", accessToken.AccessToken))))

	}
}
