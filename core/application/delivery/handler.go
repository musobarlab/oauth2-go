package delivery

import (
	"encoding/json"
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/satori/go.uuid"

	appModel "github.com/musobarlab/oauth2-go/core/application/model"
	appRepo "github.com/musobarlab/oauth2-go/core/application/repository"

	appSecurity "github.com/musobarlab/oauth2-go/core/application/security"
	userModel "github.com/musobarlab/oauth2-go/core/user/model"
	userRepo "github.com/musobarlab/oauth2-go/core/user/repository"

	jwtGen "github.com/musobarlab/oauth2-go/core/user/token"
)

// Handler model
type Handler struct {
	AppRepo              appRepo.Repository
	UserRepo             userRepo.Repository
	Security             appSecurity.Interface
	AccessTokenGenerator jwtGen.AccessTokenGenerator
}

// GetAuthorizeUser http handler
// this handler will used by client to authorize their app
// http://localhost:9000/get_authorize_user?response_type=code&client_id=58a1a940-5432-4046-8e54-18059f070ebd&redirect_uri=localhost:8000/callback
func (h *Handler) GetAuthorizeUser() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var tmpl *template.Template

		message := struct {
			Done    bool
			Message string
		}{
			Done: false,
		}

		c, err := req.Cookie("user_id")
		if err != nil {
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			message.Message = "you should login first"

			tmpl.Execute(res, message)
			return
		}

		userID := c.Value

		output := h.UserRepo.FindByID(userID)
		if output.Error != nil {
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			message.Message = "invalid session"

			tmpl.Execute(res, message)
			return
		}

		userRes := output.Result.(*userModel.User)

		responseType, ok := req.URL.Query()["response_type"]
		if !ok {
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			message.Message = "response type is required"

			tmpl.Execute(res, message)
			return
		}

		if responseType[0] != "code" {
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			message.Message = "invalid response type is required"

			tmpl.Execute(res, message)
			return
		}

		clientIDs, ok := req.URL.Query()["client_id"]
		if !ok {
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			message.Message = "client id is required"

			tmpl.Execute(res, message)
			return
		}

		redirectURIs, ok := req.URL.Query()["redirect_uri"]
		if !ok {
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			message.Message = "redirect uri is required"

			tmpl.Execute(res, message)
			return
		}

		// state, ok := req.URL.Query()["state"]
		// if !ok {
		// 	tmpl = template.Must(template.ParseFiles("./static/error.html"))
		// 	message.Message = "state is required"

		// 	tmpl.Execute(res, message)
		// 	return
		// }

		outputApp := h.AppRepo.FindByID(clientIDs[0])
		if outputApp.Error != nil {
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			message.Message = outputApp.Error.Error()

			tmpl.Execute(res, message)
			return
		}

		app := outputApp.Result.(*appModel.Application)

		if app.RedirectURI != redirectURIs[0] {
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			message.Message = "redirect uri is not equal to your redirect uri app"

			tmpl.Execute(res, message)
			return
		}

		code := fmt.Sprintf("%s|%s|%s", userRes.ID, app.ClientID, app.RedirectURI)

		encryptedCode, err := h.Security.Encrypt(code)

		http.Redirect(res, req, fmt.Sprintf("%s?code=%s", app.RedirectURI, encryptedCode), 302)

	}
}

// OAuth2Handler http handler
// localhost:9000/api/oauth2/token
// payload:
// {
// 	"grant_type": "authorization_code",
// 	"code": "wI2kNEvM0EcAZEtKKE2k4Ki3rL6drFWVI_YxmniYwqgjSSA2eQ78UnW6LbwaxubS-L4JXQcVTsORsSQf8IPijmuRFoxLM0c3_2TmzD_m9GK9pdSaQDpVczuOCJECBuNV52m4TDudn-s0kpvlASwTKwVp2bGLMu6d",
// 	"redirect_uri": "http://localhost:8000/callback",
// 	"client_id": "c4c96bb4-8979-42b3-a09d-e52b7584345e",
// 	"client_secret": "TfPeCSvWPU"
// }
func (h *Handler) OAuth2Handler() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			res.Header().Add("Content-Type", "application/json")
			res.WriteHeader(400)
			res.Write([]byte(`{"success": false, "code": 400, "message": "invalid method"}`))
			return
		}

		var oauth2Payload appModel.OAuth2
		if err := json.NewDecoder(req.Body).Decode(&oauth2Payload); err != nil {
			res.Header().Add("Content-Type", "application/json")
			res.WriteHeader(400)
			res.Write([]byte(`{"success": false, "code": 400, "message": "invalid payload"}`))
			return
		}

		if oauth2Payload.GrantType != "authorization_code" {
			res.Header().Add("Content-Type", "application/json")
			res.WriteHeader(400)
			res.Write([]byte(`{"success": false, "code": 400, "message": "invalid grant_type"}`))
			return
		}

		code, err := h.Security.Decrypt(oauth2Payload.Code)
		if err != nil {
			res.Header().Add("Content-Type", "application/json")
			res.WriteHeader(400)
			res.Write([]byte(`{"success": false, "code": 400, "message": "invalid code"}`))
			return
		}

		codes := strings.Split(code, "|")
		userID := codes[0]
		clientID := codes[1]
		redirectURI := codes[2]
		fmt.Println(codes)

		output := h.UserRepo.FindByID(userID)
		if output.Error != nil {
			res.Header().Add("Content-Type", "application/json")
			res.WriteHeader(400)
			res.Write([]byte(`{"success": false, "code": 400, "message": "user not found"}`))
			return
		}

		userRes := output.Result.(*userModel.User)

		outputApp := h.AppRepo.FindByID(clientID)
		if outputApp.Error != nil {
			res.Header().Add("Content-Type", "application/json")
			res.WriteHeader(400)
			res.Write([]byte(`{"success": false, "code": 400, "message": "client app found"}`))
			return
		}

		app := outputApp.Result.(*appModel.Application)

		if app.RedirectURI != redirectURI {
			res.Header().Add("Content-Type", "application/json")
			res.WriteHeader(400)
			res.Write([]byte(`{"success": false, "code": 400, "message": "redirect uri is not equal to your redirect uri app"}`))
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
		res.Write([]byte(fmt.Sprintf(`{"success": false, "code": 200, "message": "exchange access token", "data": "%s"}`, fmt.Sprintf("Bearer %s", accessToken.AccessToken))))

	}
}

// IndexHandler http handler
func (h *Handler) IndexHandler() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var tmpl *template.Template

		message := struct {
			Done bool
		}{
			Done: false,
		}

		tmpl = template.Must(template.ParseFiles("./static/index.html"))
		tmpl.Execute(res, message)

	}
}

// GetRegisterHandler http handler
func (h *Handler) GetRegisterHandler() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var tmpl *template.Template

		message := struct {
			Done bool
		}{
			Done: false,
		}

		tmpl = template.Must(template.ParseFiles("./static/new_app.html"))
		tmpl.Execute(res, message)

	}
}

// PostRegisterHandler http handler
func (h *Handler) PostRegisterHandler() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var tmpl *template.Template

		message := struct {
			Done         bool
			Message      string
			Name         string
			ClientID     string
			ClientSecret string
			RedirectURI  string
		}{
			Message: "invalid method",
		}

		if req.Method != http.MethodPost {
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			tmpl.Execute(res, message)
			return
		}

		appName := req.FormValue("app_name")
		redirectURI := req.FormValue("redirect_uri")

		if len(appName) <= 0 {
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			message.Message = "app name is required"

			tmpl.Execute(res, message)
			return
		}

		if len(redirectURI) <= 0 {
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			message.Message = "redirect URI is required"

			tmpl.Execute(res, message)
			return
		}

		clientID := uuid.NewV4().String()
		clientSecret := generateSecret(10)

		output := h.AppRepo.Save(&appModel.Application{
			Name:         appName,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
		})

		if output.Error != nil {
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			message.Message = output.Error.Error()

			tmpl.Execute(res, message)
			return
		}

		app := output.Result.(*appModel.Application)

		tmpl = template.Must(template.ParseFiles("./static/index.html"))
		message.Message = "Your are ready to go"
		message.Done = true
		message.Name = app.Name
		message.ClientID = app.ClientID
		message.ClientSecret = app.ClientSecret
		message.RedirectURI = app.RedirectURI
		tmpl.Execute(res, message)

	}
}

// ListAppHandler http handler
func (h *Handler) ListAppHandler() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var tmpl *template.Template

		message := struct {
			Data    []*appModel.Application
			Message string
		}{
			Message: "About OAuth2 flow",
		}

		output := h.AppRepo.FindAll()

		if output.Error != nil {
			tmpl = template.Must(template.ParseFiles("./static/error.html"))
			message.Message = output.Error.Error()

			tmpl.Execute(res, message)
			return
		}

		apps := output.Result.([]*appModel.Application)

		tmpl = template.Must(template.ParseFiles("./static/list_app.html"))
		message.Data = apps
		tmpl.Execute(res, message)

	}
}

// AboutHandler http handler
func (h *Handler) AboutHandler() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var tmpl *template.Template

		message := struct {
			Message string
		}{
			Message: "About OAuth2 flow",
		}

		tmpl = template.Must(template.ParseFiles("./static/about.html"))
		tmpl.Execute(res, message)

	}
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func stringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func generateSecret(length int) string {
	return stringWithCharset(length, charset)
}
