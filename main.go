package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

const browserUA = "Dalvik/2.1.0 (Linux; U; Android 16; SM-S901W Build/BP2A.250605.031.A3)"
const clientID = "4b3a6465-94dd-47c2-976c-18bc29c53c2f"

type ExchangedAuthTokenResponse struct {
	AccessToken           string `json:"access_token"`
	IDToken               string `json:"id_token"`
	TokenType             string `json:"token_type"`
	NotBefore             int    `json:"not_before"`
	ExpiresIn             int    `json:"expires_in"`
	ExpiresOn             int    `json:"expires_on"`
	Resource              string `json:"resource"`
	ClientInfo            string `json:"client_info"`
	Scope                 string `json:"scope"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int    `json:"refresh_token_expires_in"`
}

func expect(req *http.Request, resp *http.Response, status int) error {
	if resp.StatusCode != status {
		respText, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected response code %v %v %v: %v", resp.StatusCode, req.Method, req.URL, string(respText))

	}
	return nil
}

func NewCodeVerifier() string {
	return "DM6nhvQSKnj72gkQQ5T1tCgCYGy5vdXnzdIQw3Bh46TX7pDvAcisyWDyt5UL3NQH8q4NoqMvRICQRmxCeDU3qHj8Jvciqo4RHcRiyjIlbB9q0k8LnUu8zHIdJHRLtk3J" // idc
}

func CodeVerifierToChallenge(codeVerifier string) string {
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func NewLoginURL(codeVerifier string) string {
	data := url.Values{}
	data.Set("scope", "https://wattsb2cap02.onmicrosoft.com/wattsapiresi/manage+offline_access+openid+profile")
	data.Set("response_type", "code")
	data.Set("client_id", clientID)
	data.Set("redirect_uri", "msal"+clientID+"://auth")
	data.Set("prompt", "login")
	data.Set("code_challenge", CodeVerifierToChallenge(codeVerifier))
	data.Set("code_challenge_method", "S256")
	data.Set("client_info", "1")
	data.Set("haschrome", "1")
	return fmt.Sprintf("https://login.watts.io/tfp/wattsb2cap02.onmicrosoft.com/B2C_1A_Residential_UnifiedSignUpOrSignIn/oauth2/v2.0/authorize?%v", data.Encode())
}

func LoginSelfAsserted(codeVerifier, username, password string) (string, error) {
	jar, _ := cookiejar.New(nil)

	client := http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// initial cookie booting
	loginURL := NewLoginURL(codeVerifier)
	req, _ := http.NewRequest("GET", loginURL, nil)
	req.Header.Set("User-Agent", browserUA)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	if err := expect(req, resp, http.StatusOK); err != nil {
		resp.Body.Close()
		return "", err
	}
	resp.Body.Close()
	var csrf string
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "x-ms-cpim-csrf" {
			csrf = cookie.Value
			break
		}
	}
	if csrf == "" {
		return "", errors.New("no csrf cookie found :(")
	}
	var transaction string
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "x-ms-cpim-trans" {
			type TransCookieStructure struct {
				TDic []struct {
					I string `json:"I"`
					T string `json:"T"`
					P string `json:"P"`
					C string `json:"C"`
					S int    `json:"S"`
					M struct {
					} `json:"M"`
					D int    `json:"D"`
					E string `json:"E"`
				} `json:"T_DIC"`
				CID string `json:"C_ID"`
			}
			dec, err := base64.StdEncoding.DecodeString(cookie.Value)
			if err != nil {
				return "", fmt.Errorf("failed to decode x-ms-cpim-trans cookie %v: %v", cookie.Value, err)
			}
			var unm TransCookieStructure
			if err := json.Unmarshal(dec, &unm); err != nil {
				return "", fmt.Errorf("failed to unmarshal x-ms-cpim-trans decoded cookie value %v: %v", dec, err)
			}
			transaction = unm.CID
		}
	}
	if transaction == "" {
		return "", errors.New("no transaction cookie found :(")
	}
	transactionEncoded := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("{\"TID\":\"%v\"}", transaction)))

	// submitting login form
	data := url.Values{}
	data.Set("request_type", "RESPONSE")
	data.Set("signInName", username)
	data.Set("password", password)
	selfAssertedURL := fmt.Sprintf("https://login.watts.io/wattsb2cap02.onmicrosoft.com/B2C_1A_Residential_UnifiedSignUpOrSignIn/SelfAsserted?tx=StateProperties=%v&p=B2C_1A_Residential_UnifiedSignUpOrSignIn", transactionEncoded)
	req, _ = http.NewRequest("POST", selfAssertedURL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Referer", loginURL)
	req.Header.Set("X-CSRF-TOKEN", csrf)

	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	if err := expect(req, resp, http.StatusOK); err != nil {
		resp.Body.Close()
		return "", err
	}
	resp.Body.Close()

	// confirming token
	confirmURL := fmt.Sprintf("https://login.watts.io/wattsb2cap02.onmicrosoft.com/B2C_1A_Residential_UnifiedSignUpOrSignIn/api/CombinedSigninAndSignup/confirmed?rememberMe=true&csrf_token=%v&tx=StateProperties=%v", csrf, transactionEncoded)
	req, _ = http.NewRequest("GET", confirmURL, nil)
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Referer", loginURL)

	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	if err := expect(req, resp, http.StatusFound); err != nil {
		resp.Body.Close()
		return "", err
	}
	resp.Body.Close()

	redir, err := resp.Location()
	if err != nil {
		return "", err
	}

	code := redir.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("no code parameter found in redirect: %v", redir)
	}

	return code, nil
}

func ExchangeAuthToken(code, codeVerifier string) (ExchangedAuthTokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", "https://wattsb2cap02.onmicrosoft.com/wattsapiresi/manage+offline_access+openid+profile")
	data.Set("client_info", "1")
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", "msal"+clientID+"://auth")
	data.Set("code_verifier", codeVerifier)

	req, err := http.NewRequest("POST", "https://login.watts.io/tfp/wattsb2cap02.onmicrosoft.com/B2C_1A_Residential_UnifiedSignUpOrSignIn/oauth2/v2.0/token?haschrome=1", strings.NewReader(strings.ReplaceAll(data.Encode(), "%2B", "+")))
	if err != nil {
		return ExchangedAuthTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", browserUA)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ExchangedAuthTokenResponse{}, err
	}
	defer resp.Body.Close()

	if err := expect(req, resp, http.StatusOK); err != nil {
		resp.Body.Close()
		return ExchangedAuthTokenResponse{}, err
	}

	var decoded ExchangedAuthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return ExchangedAuthTokenResponse{}, err
	}

	return decoded, nil
}

const apiBaseURL = "https://home.watts.com/api"

type APIWrappedResponse[T any] struct {
	ErrorNumber  int `json:"errorNumber"`
	ErrorMessage any `json:"errorMessage"`
	Body         T   `json:"body"`
}

func API[T any](method, path string, body io.Reader, expectedStatus int, decode bool, token string) (T, error) {
	req, err := http.NewRequest(method, apiBaseURL+path, body)
	if err != nil {
		return *new(T), err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Api-Version", "2.0")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return *new(T), err
	}
	defer resp.Body.Close()

	if err := expect(req, resp, http.StatusOK); err != nil {
		return *new(T), err
	}

	var data T

	if decode {
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return *new(T), err
		}
	}

	return data, nil
}

func Get[T any](path, token string) (T, error) {
	return API[T]("GET", path, nil, http.StatusOK, true, token)
}

// func Patch[T any](path, token string, body io.Reader) (T, error) {
// 	return API[T]("PATCH", path, body, http.StatusOK, true, token)
// }

// func PatchJ[T any](path, token string, body any) (T, error) {
// 	d, err := json.Marshal(body)
// 	if err != nil {
// 		return *new(T), err
// 	}
// 	return Patch[T](path, token, bytes.NewReader(d))
// }

type UserDetails struct {
	UserID                   string `json:"userId"`
	EmailAddress             string `json:"emailAddress"`
	DefaultLocationID        string `json:"defaultLocationId"`
	LanguagePreference       string `json:"languagePreference"`
	UserTypeID               int    `json:"userTypeId"`
	MeasurementScale         string `json:"measurementScale"`
	MobilePhoneNumber        string `json:"mobilePhoneNumber"`
	FirstName                string `json:"firstName"`
	LastName                 string `json:"lastName"`
	SmsNotificationEnabled   bool   `json:"smsNotificationEnabled"`
	EmailNotificationEnabled bool   `json:"emailNotificationEnabled"`
	PushNotificationEnabled  bool   `json:"pushNotificationEnabled"`
	DefaultLocationDevices   []any  `json:"defaultLocationDevices"`
	VoiceControlPlatform     string `json:"voiceControlPlatform"`
}

func GetUserDetails(token string) (APIWrappedResponse[UserDetails], error) {
	return Get[APIWrappedResponse[UserDetails]]("/User/Details", token)
}

type Location struct {
	Address struct {
		Address       string `json:"address"`
		Address2      string `json:"address2"`
		City          string `json:"city"`
		Country       string `json:"country"`
		StateProvince string `json:"state_province"`
		Zipcode       string `json:"zipcode"`
	} `json:"address"`
	AwayState                      int    `json:"awayState"`
	DevicesCount                   int    `json:"devicesCount"`
	HasDeviceInDemandResponseEvent bool   `json:"hasDeviceInDemandResponseEvent"`
	IsDefault                      bool   `json:"isDefault"`
	IsShared                       bool   `json:"isShared"`
	LocationID                     string `json:"locationId"`
	Name                           string `json:"name"`
	OwnerID                        string `json:"ownerId"`
	SupportsAway                   bool   `json:"supportsAway"`
	UserType                       int    `json:"userType"`
	UsersCount                     int    `json:"usersCount"`
}

func GetLocations(token string) (APIWrappedResponse[[]Location], error) {
	return Get[APIWrappedResponse[[]Location]]("/Location", token)
}

func SetLocationAwayState(locationID string, away bool, token string) error {
	awayState := 0
	if away {
		awayState = 1
	}
	d, err := json.Marshal(map[string]any{
		"awayState": awayState,
	})
	if err != nil {
		return err
	}

	_, err = API[any]("PATCH", fmt.Sprintf("/Location/%v/State", url.PathEscape(locationID)), bytes.NewReader(d), http.StatusOK, false, token)
	return err
}

// SetDeviceTemperature sets the heat and/or cool target on a device.
// When a schedule is active, the API expects "HeatHold"/"CoolHold" keys;
// otherwise it expects "Heat"/"Cool".
func SetDeviceTemperature(deviceID string, scheduleActive bool, heat, cool *float64, token string) error {
	settings := map[string]any{}

	if heat != nil {
		if scheduleActive {
			settings["HeatHold"] = *heat
		} else {
			settings["Heat"] = *heat
		}
	}
	if cool != nil {
		if scheduleActive {
			settings["CoolHold"] = *cool
		} else {
			settings["Cool"] = *cool
		}
	}

	d, err := json.Marshal(map[string]any{
		"Settings": settings,
	})
	if err != nil {
		return err
	}

	_, err = API[any]("PATCH", fmt.Sprintf("/Device/%v", url.PathEscape(deviceID)), bytes.NewReader(d), http.StatusOK, false, token)
	return err
}

func SetDeviceMode(deviceID, mode, token string) error {
	d, err := json.Marshal(map[string]any{
		"Settings": map[string]any{
			"Mode": mode,
		},
	})
	if err != nil {
		return err
	}

	_, err = API[any]("PATCH", fmt.Sprintf("/Device/%v", url.PathEscape(deviceID)), bytes.NewReader(d), http.StatusOK, false, token)
	return err
}

func SetDeviceFanMode(deviceID, fanMode, token string) error {
	d, err := json.Marshal(map[string]any{
		"Settings": map[string]any{
			"Fan": fanMode,
		},
	})
	if err != nil {
		return err
	}

	_, err = API[any]("PATCH", fmt.Sprintf("/Device/%v", url.PathEscape(deviceID)), bytes.NewReader(d), http.StatusOK, false, token)
	return err
}

type ScheduleSetting struct {
	// Cool to this temp
	C float64 `json:"C"`
	// Heat to this temp
	H float64 `json:"H"`
	// Time of event, ex, 07:00
	T string `json:"T"`
}

type ScheduleGroup struct {
	// Consists of one or more of the following characters:
	// - M: Monday
	// - T: Tuesday
	// - W: Wednesday
	// - R: Thursday
	// - F: Friday
	// - A: Saturday
	// - S: Sunday
	Days string `json:"Days"`
	// Wake
	W ScheduleSetting `json:"W"`
	// Leave
	L ScheduleSetting `json:"L"`
	// Return
	R ScheduleSetting `json:"R"`
	// Sleep
	S ScheduleSetting `json:"S"`
}

const SensorStatusAbsent = "Absent"
const SensorStatusOkay = "Okay"

type Sensor[T any] struct {
	Status string `json:"Status"`
	Value  T      `json:"Val"`
}

// This is the schema for a single type of device - my thermostat. Not sure about others.
type MyDevice struct {
	Data struct {
		DateTime time.Time `json:"DateTime"`
		Dehum    struct {
			Active int `json:"Active"`
			Max    int `json:"Max"`
			Min    int `json:"Min"`
			Steps  int `json:"Steps"`
			Val    int `json:"Val"`
		} `json:"Dehum"`
		Energy struct {
			Cool struct {
				Daily   []float64 `json:"Daily"`
				Monthly []float64 `json:"Monthly"`
			} `json:"Cool"`
			Heat struct {
				Daily   []float64 `json:"Daily"`
				Monthly []float64 `json:"Monthly"`
			} `json:"Heat"`
		} `json:"Energy"`
		Fan struct {
			Active int      `json:"Active"`
			Enum   []string `json:"Enum"`
			Relay  int      `json:"Relay"`
			Val    string   `json:"Val"`
		} `json:"Fan"`
		Hum struct {
			Active int `json:"Active"`
			Max    int `json:"Max"`
			Min    int `json:"Min"`
			Steps  int `json:"Steps"`
			Val    int `json:"Val"`
		} `json:"Hum"`
		HumInterlock int `json:"HumInterlock"`
		Mode         struct {
			Active int      `json:"Active"`
			Enum   []string `json:"Enum"`
			Val    string   `json:"Val"`
		} `json:"Mode"`
		OpenADR struct {
			Active int      `json:"Active"`
			Enum   []string `json:"Enum"`
			Val    string   `json:"Val"`
		} `json:"OpenADR"`
		SchedEnable struct {
			Active int      `json:"Active"`
			Enum   []string `json:"Enum"`
			Val    string   `json:"Val"`
		} `json:"SchedEnable"`
		Schedule struct {
			CoolActive  int           `json:"CoolActive"`
			CoolMax     float64       `json:"CoolMax"`
			CoolMin     float64       `json:"CoolMin"`
			Event       string        `json:"Event"`
			FloorActive int           `json:"FloorActive"`
			FloorMax    float64       `json:"FloorMax"`
			FloorMin    float64       `json:"FloorMin"`
			Grp         int           `json:"Grp"`
			Grp1        ScheduleGroup `json:"Grp1"`
			Grp2        ScheduleGroup `json:"Grp2"`
			Grp3        ScheduleGroup `json:"Grp3"`
			Grp4        ScheduleGroup `json:"Grp4"`
			Grp5        ScheduleGroup `json:"Grp5"`
			Grp6        ScheduleGroup `json:"Grp6"`
			Grp7        ScheduleGroup `json:"Grp7"`
			HeatActive  int           `json:"HeatActive"`
			HeatMax     float64       `json:"HeatMax"`
			HeatMin     float64       `json:"HeatMin"`
			SchedActive int           `json:"SchedActive"`
			TempSteps   float64       `json:"TempSteps"`
			TimeSteps   int           `json:"TimeSteps"`
		} `json:"Schedule"`
		Sensors struct {
			Floor   Sensor[float64] `json:"Floor"`
			Outdoor Sensor[float64] `json:"Outdoor"`
			Rh      Sensor[float64] `json:"RH"`
			Room    Sensor[float64] `json:"Room"`
		} `json:"Sensors"`
		State struct {
			// Known values: "Off"
			Op  string `json:"Op"`
			Sub string `json:"Sub"`
		} `json:"State"`
		TZOffset int `json:"TZOffset"`
		Target   struct {
			Active int     `json:"Active"`
			Cool   float64 `json:"Cool"`
			Heat   float64 `json:"Heat"`
			Hold   float64 `json:"Hold"`
			Max    float64 `json:"Max"`
			Min    float64 `json:"Min"`
			Sensor string  `json:"Sensor"`
			Steps  float64 `json:"Steps"`
		} `json:"Target"`
		TempInterlock float64 `json:"TempInterlock"`
		TempUnits     struct {
			Active int      `json:"Active"`
			Enum   []string `json:"Enum"`
			Val    string   `json:"Val"`
		} `json:"TempUnits"`
		Units string `json:"Units"`
	} `json:"data"`
	DeviceID     string `json:"deviceId"`
	DeviceType   string `json:"deviceType"`
	DeviceTypeID int    `json:"deviceTypeId"`
	ImageURL     any    `json:"imageUrl"`
	IsConnected  bool   `json:"isConnected"`
	IsShared     bool   `json:"isShared"`
	Location     struct {
		Address struct {
			Address       string `json:"address"`
			Address2      string `json:"address2"`
			City          string `json:"city"`
			Country       string `json:"country"`
			StateProvince string `json:"state_province"`
			Zipcode       string `json:"zipcode"`
		} `json:"address"`
		AwayState  int    `json:"awayState"`
		LocationID string `json:"locationId"`
		Name       string `json:"name"`
		UserType   int    `json:"userType"`
	} `json:"location"`
	ModelID        int    `json:"modelId"`
	ModelNumber    string `json:"modelNumber"`
	Name           string `json:"name"`
	RequestingUser string `json:"requestingUser"`
}

func GetDevices(locationID, token string) (APIWrappedResponse[[]MyDevice], error) {
	return Get[APIWrappedResponse[[]MyDevice]](fmt.Sprintf("/Location/%v/Devices", url.PathEscape(locationID)), token)
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func RefreshAuthToken(refreshToken string) (ExchangedAuthTokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", "https://wattsb2cap02.onmicrosoft.com/wattsapiresi/manage+offline_access+openid+profile")
	data.Set("client_info", "1")
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequest("POST", "https://login.watts.io/tfp/wattsb2cap02.onmicrosoft.com/B2C_1A_Residential_UnifiedSignUpOrSignIn/oauth2/v2.0/token?haschrome=1", strings.NewReader(strings.ReplaceAll(data.Encode(), "%2B", "+")))
	if err != nil {
		return ExchangedAuthTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", browserUA)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ExchangedAuthTokenResponse{}, err
	}
	defer resp.Body.Close()

	if err := expect(req, resp, http.StatusOK); err != nil {
		return ExchangedAuthTokenResponse{}, err
	}

	var decoded ExchangedAuthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return ExchangedAuthTokenResponse{}, err
	}

	return decoded, nil
}

func authenticate(username, pass, tokensPath string) ExchangedAuthTokenResponse {
	var tokens ExchangedAuthTokenResponse

	previousTokensData, err := os.ReadFile(tokensPath)

	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("failed to read previous tokens: %v", err)
	}

	if err == nil {
		if err := json.Unmarshal(previousTokensData, &tokens); err != nil {
			log.Fatalf("failed to read old tokens file: %v", err)
		}
		log.Println("read old tokens")
		if tokens.ExpiresOn < int(time.Now().Add(time.Minute).Unix()) {
			log.Println("old tokens are expired, trying refresh")
			if tokens.RefreshToken != "" {
				refreshed, err := RefreshAuthToken(tokens.RefreshToken)
				if err != nil {
					log.Printf("refresh failed, will re-login: %v", err)
					tokens = ExchangedAuthTokenResponse{}
				} else {
					log.Println("refreshed tokens successfully")
					tokens = refreshed
					tokensMarshalled, _ := json.Marshal(tokens)
					os.WriteFile(tokensPath, tokensMarshalled, os.ModePerm)
				}
			} else {
				tokens = ExchangedAuthTokenResponse{}
			}
		}
	}

	if os.IsNotExist(err) || tokens.AccessToken == "" {
		verifier := NewCodeVerifier()
		code, err := LoginSelfAsserted(verifier, username, pass)
		if err != nil {
			log.Fatal(err)
		}
		tokens, err = ExchangeAuthToken(code, verifier)
		if err != nil {
			log.Fatal(err)
		}
		tokensMarshalled, _ := json.Marshal(tokens)
		os.WriteFile(tokensPath, tokensMarshalled, os.ModePerm)
		log.Println("new tokens")
	}

	return tokens
}

// wattsToHAMode maps Watts API mode values to Home Assistant HVAC modes.
func wattsToHAMode(wattsMode string) string {
	switch strings.ToLower(wattsMode) {
	case "heat":
		return "heat"
	case "cool":
		return "cool"
	case "auto", "heat-cool":
		return "heat_cool"
	case "off":
		return "off"
	case "fan":
		return "fan_only"
	case "dry", "dehumidify":
		return "dry"
	default:
		return strings.ToLower(wattsMode)
	}
}

// haToWattsMode maps Home Assistant HVAC modes back to Watts API mode values.
func haToWattsMode(haMode string) string {
	switch haMode {
	case "heat":
		return "Heat"
	case "cool":
		return "Cool"
	case "heat_cool":
		return "Auto"
	case "off":
		return "Off"
	case "fan_only":
		return "Fan"
	case "dry":
		return "Dry"
	default:
		return haMode
	}
}

// wattsToHAAction maps Watts operational state to HA HVAC action.
func wattsToHAAction(op string) string {
	switch strings.ToLower(op) {
	case "heat", "heating":
		return "heating"
	case "cool", "cooling":
		return "cooling"
	case "off":
		return "off"
	case "idle", "":
		return "idle"
	default:
		return "idle"
	}
}

func mqttTopicPrefix(deviceID string) string {
	return fmt.Sprintf("watts/%s", deviceID)
}

func publishDiscovery(client mqtt.Client, device MyDevice) {
	prefix := mqttTopicPrefix(device.DeviceID)

	// Map available modes from the device
	var haModes []string
	for _, m := range device.Data.Mode.Enum {
		haModes = append(haModes, wattsToHAMode(m))
	}
	// Ensure "off" is always present
	hasOff := false
	for _, m := range haModes {
		if m == "off" {
			hasOff = true
			break
		}
	}
	if !hasOff {
		haModes = append(haModes, "off")
	}

	// Check if heat_cool (dual setpoint) is supported
	hasDualSetpoint := false
	for _, m := range haModes {
		if m == "heat_cool" {
			hasDualSetpoint = true
			break
		}
	}

	config := map[string]any{
		"name":                      device.Name,
		"unique_id":                 fmt.Sprintf("watts_%s", device.DeviceID),
		"mode_command_topic":        prefix + "/mode/set",
		"mode_state_topic":          prefix + "/mode/state",
		"current_temperature_topic": prefix + "/current_temp",
		"action_topic":              prefix + "/action",
		"availability_topic":        prefix + "/availability",
		"modes":                     haModes,
		"min_temp":                  device.Data.Target.Min,
		"max_temp":                  device.Data.Target.Max,
		"temp_step":                 device.Data.Target.Steps,
		"temperature_unit":          device.Data.TempUnits.Val,
		"optimistic":                true,
		"device": map[string]any{
			"identifiers":  []string{fmt.Sprintf("watts_%s", device.DeviceID)},
			"name":         device.Name,
			"manufacturer": "Watts",
			"model":        device.ModelNumber,
		},
	}

	// Temperature command topics
	config["temperature_command_topic"] = prefix + "/temp/set"
	config["temperature_state_topic"] = prefix + "/temp/state"

	if hasDualSetpoint {
		config["temperature_high_command_topic"] = prefix + "/temp_high/set"
		config["temperature_high_state_topic"] = prefix + "/temp_high/state"
		config["temperature_low_command_topic"] = prefix + "/temp_low/set"
		config["temperature_low_state_topic"] = prefix + "/temp_low/state"
	}

	if len(device.Data.Fan.Enum) > 0 {
		config["fan_mode_command_topic"] = prefix + "/fan/set"
		config["fan_mode_state_topic"] = prefix + "/fan/state"
		config["fan_modes"] = device.Data.Fan.Enum
	}

	if device.Data.Sensors.Rh.Status == SensorStatusOkay {
		config["current_humidity_topic"] = prefix + "/current_humidity"
	}

	payload, _ := json.Marshal(config)
	discoveryTopic := fmt.Sprintf("homeassistant/climate/watts_%s/config", device.DeviceID)

	token := client.Publish(discoveryTopic, 1, true, payload)
	token.Wait()
	if token.Error() != nil {
		log.Printf("failed to publish discovery for %s: %v", device.DeviceID, token.Error())
	} else {
		log.Printf("published discovery config for %s on %s", device.Name, discoveryTopic)
	}

	// Outdoor temperature sensor
	if device.Data.Sensors.Outdoor.Status == SensorStatusOkay {
		sensorConfig := map[string]any{
			"name":                "Outdoor Temperature",
			"unique_id":           fmt.Sprintf("watts_%s_outdoor_temp", device.DeviceID),
			"state_topic":         prefix + "/outdoor_temp",
			"availability_topic":  prefix + "/availability",
			"device_class":        "temperature",
			"state_class":         "measurement",
			"unit_of_measurement": "°" + device.Data.TempUnits.Val,
			"device": map[string]any{
				"identifiers":  []string{fmt.Sprintf("watts_%s", device.DeviceID)},
				"name":         device.Name,
				"manufacturer": "Watts",
				"model":        device.ModelNumber,
			},
		}
		sensorPayload, _ := json.Marshal(sensorConfig)
		sensorTopic := fmt.Sprintf("homeassistant/sensor/watts_%s_outdoor_temp/config", device.DeviceID)
		t := client.Publish(sensorTopic, 1, true, sensorPayload)
		t.Wait()
		if t.Error() != nil {
			log.Printf("failed to publish outdoor temp discovery for %s: %v", device.DeviceID, t.Error())
		}
	}
}

func publishState(client mqtt.Client, device MyDevice) {
	prefix := mqttTopicPrefix(device.DeviceID)

	pub := func(topic, value string) {
		t := client.Publish(prefix+"/"+topic, 0, true, value)
		t.Wait()
	}

	// Availability
	if device.IsConnected {
		pub("availability", "online")
	} else {
		pub("availability", "offline")
	}

	// Current temperature
	if device.Data.Sensors.Room.Status == SensorStatusOkay {
		pub("current_temp", fmt.Sprintf("%.1f", device.Data.Sensors.Room.Value))
	}

	// Current humidity
	if device.Data.Sensors.Rh.Status == SensorStatusOkay {
		pub("current_humidity", fmt.Sprintf("%.1f", device.Data.Sensors.Rh.Value))
	}

	// Mode
	haMode := wattsToHAMode(device.Data.Mode.Val)
	pub("mode/state", haMode)

	// Target temperatures
	switch haMode {
	case "heat_cool":
		// Dual setpoint: publish both high (cool) and low (heat) targets
		pub("temp_high/state", fmt.Sprintf("%.1f", device.Data.Target.Cool))
		pub("temp_low/state", fmt.Sprintf("%.1f", device.Data.Target.Heat))
		// Single target isn't meaningful in this mode, but publish heat as default
		pub("temp/state", fmt.Sprintf("%.1f", device.Data.Target.Heat))
	case "cool":
		pub("temp/state", fmt.Sprintf("%.1f", device.Data.Target.Cool))
	case "heat":
		pub("temp/state", fmt.Sprintf("%.1f", device.Data.Target.Heat))
	default:
		// For off/fan_only/dry, publish whatever is there
		pub("temp/state", fmt.Sprintf("%.1f", device.Data.Target.Heat))
	}

	// Outdoor temperature
	if device.Data.Sensors.Outdoor.Status == SensorStatusOkay {
		pub("outdoor_temp", fmt.Sprintf("%.1f", device.Data.Sensors.Outdoor.Value))
	}

	// Fan mode
	if device.Data.Fan.Val != "" {
		pub("fan/state", device.Data.Fan.Val)
	}

	// Action (what the system is currently doing)
	pub("action", wattsToHAAction(device.Data.State.Op))
}

// deviceState tracks the latest known state of each device so command
// handlers can determine whether a schedule is active.
type deviceState struct {
	mu      sync.RWMutex
	devices map[string]MyDevice // keyed by deviceID
}

func (ds *deviceState) Update(devices []MyDevice) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for _, d := range devices {
		ds.devices[d.DeviceID] = d
	}
}

func (ds *deviceState) Get(deviceID string) (MyDevice, bool) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	d, ok := ds.devices[deviceID]
	return d, ok
}

func (ds *deviceState) IsScheduleActive(deviceID string) bool {
	d, ok := ds.Get(deviceID)
	if !ok {
		return false
	}
	return strings.ToLower(d.Data.SchedEnable.Val) == "on" || strings.ToLower(d.Data.SchedEnable.Val) == "enabled"
}

func subscribeCommands(client mqtt.Client, device MyDevice, state *deviceState, tokens *ExchangedAuthTokenResponse, username, pass, tokensPath string, tokensMu *sync.Mutex, pubSync chan bool) {
	prefix := mqttTopicPrefix(device.DeviceID)
	deviceID := device.DeviceID

	getToken := func() string {
		tokensMu.Lock()
		defer tokensMu.Unlock()
		if tokens.ExpiresOn < int(time.Now().Add(2*time.Minute).Unix()) {
			*tokens = authenticate(username, pass, tokensPath)
		}
		return tokens.AccessToken
	}

	// Single setpoint (used in heat-only or cool-only modes)
	client.Subscribe(prefix+"/temp/set", 1, func(_ mqtt.Client, msg mqtt.Message) {
		val, err := strconv.ParseFloat(string(msg.Payload()), 64)
		if err != nil {
			log.Printf("invalid temp value: %s", msg.Payload())
			return
		}
		dev, ok := state.Get(deviceID)
		if !ok {
			log.Printf("no known state for device %s", deviceID)
			return
		}
		schedActive := state.IsScheduleActive(deviceID)
		haMode := wattsToHAMode(dev.Data.Mode.Val)

		var heat, cool *float64
		switch haMode {
		case "cool":
			cool = &val
		default:
			heat = &val
		}

		log.Printf("setting temp on %s: heat=%v cool=%v (schedule=%v)", deviceID, heat, cool, schedActive)
		if err := SetDeviceTemperature(deviceID, schedActive, heat, cool, getToken()); err != nil {
			log.Printf("failed to set temp on %s: %v", deviceID, err)
		}
		pubSync <- true
	})

	// Dual setpoint: high (cool target)
	client.Subscribe(prefix+"/temp_high/set", 1, func(_ mqtt.Client, msg mqtt.Message) {
		val, err := strconv.ParseFloat(string(msg.Payload()), 64)
		if err != nil {
			log.Printf("invalid temp_high value: %s", msg.Payload())
			return
		}
		schedActive := state.IsScheduleActive(deviceID)
		log.Printf("setting cool target on %s: %.1f (schedule=%v)", deviceID, val, schedActive)
		if err := SetDeviceTemperature(deviceID, schedActive, nil, &val, getToken()); err != nil {
			log.Printf("failed to set cool target on %s: %v", deviceID, err)
		}
		pubSync <- true
	})

	// Dual setpoint: low (heat target)
	client.Subscribe(prefix+"/temp_low/set", 1, func(_ mqtt.Client, msg mqtt.Message) {
		val, err := strconv.ParseFloat(string(msg.Payload()), 64)
		if err != nil {
			log.Printf("invalid temp_low value: %s", msg.Payload())
			return
		}
		schedActive := state.IsScheduleActive(deviceID)
		log.Printf("setting heat target on %s: %.1f (schedule=%v)", deviceID, val, schedActive)
		if err := SetDeviceTemperature(deviceID, schedActive, &val, nil, getToken()); err != nil {
			log.Printf("failed to set heat target on %s: %v", deviceID, err)
		}
		pubSync <- true
	})

	// Mode
	client.Subscribe(prefix+"/mode/set", 1, func(_ mqtt.Client, msg mqtt.Message) {
		haMode := string(msg.Payload())
		wattsMode := haToWattsMode(haMode)
		log.Printf("setting mode on %s: %s (watts: %s)", deviceID, haMode, wattsMode)
		if err := SetDeviceMode(deviceID, wattsMode, getToken()); err != nil {
			log.Printf("failed to set mode on %s: %v", deviceID, err)
		}
		pubSync <- true
	})

	// Fan mode
	client.Subscribe(prefix+"/fan/set", 1, func(_ mqtt.Client, msg mqtt.Message) {
		fanMode := string(msg.Payload())
		log.Printf("setting fan mode on %s: %s", deviceID, fanMode)
		if err := SetDeviceFanMode(deviceID, fanMode, getToken()); err != nil {
			log.Printf("failed to set fan mode on %s: %v", deviceID, err)
		}
		pubSync <- true
	})
}

func main() {
	username := os.Getenv("WAHA_USER")
	pass := os.Getenv("WAHA_PASS")
	if username == "" || pass == "" {
		log.Fatal("WAHA_USER and WAHA_PASS are required")
	}

	tokensPath := envOrDefault("WAHA_TOKENS_PATH", "tokens.json")
	mqttBroker := envOrDefault("WAHA_MQTT_BROKER", "tcp://localhost:1883")
	mqttUser := os.Getenv("WAHA_MQTT_USER")
	mqttPass := os.Getenv("WAHA_MQTT_PASS")
	pollInterval := 5 * time.Minute

	// Authenticate with Watts API
	tokens := authenticate(username, pass, tokensPath)

	userDetails, err := GetUserDetails(tokens.AccessToken)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("hello %v", userDetails.Body.FirstName)

	locations, err := GetLocations(tokens.AccessToken)
	if err != nil {
		log.Fatal(err)
	}

	var defaultLocation Location
	for _, location := range locations.Body {
		if location.IsDefault && location.DevicesCount > 0 {
			defaultLocation = location
		} else if defaultLocation.LocationID == "" && location.DevicesCount > 0 {
			defaultLocation = location
		}
	}
	if defaultLocation.LocationID == "" {
		log.Fatal("no default location found!")
	}
	log.Printf("using location: %s", defaultLocation.Name)

	// Connect to MQTT
	opts := mqtt.NewClientOptions().
		AddBroker(mqttBroker).
		SetClientID(fmt.Sprintf("watts-bridge-%s", defaultLocation.LocationID)).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(10 * time.Second).
		SetOnConnectHandler(func(_ mqtt.Client) {
			log.Println("connected to MQTT broker")
		}).
		SetConnectionLostHandler(func(_ mqtt.Client, err error) {
			log.Printf("MQTT connection lost: %v", err)
		})

	if mqttUser != "" {
		opts.SetUsername(mqttUser)
		opts.SetPassword(mqttPass)
	}

	mqttClient := mqtt.NewClient(opts)
	if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
		log.Fatalf("failed to connect to MQTT broker: %v", token.Error())
	}

	// Initial device fetch + discovery
	devices, err := GetDevices(defaultLocation.LocationID, tokens.AccessToken)
	if err != nil {
		log.Fatalf("failed to get devices: %v", err)
	}

	var tokensMu sync.Mutex

	deviceStates := &deviceState{
		devices: map[string]MyDevice{},
	}
	deviceStates.Update(devices.Body)

	pubSync := make(chan bool)

	for _, device := range devices.Body {
		subscribeCommands(mqttClient, device, deviceStates, &tokens, username, pass, tokensPath, &tokensMu, pubSync)
		publishDiscovery(mqttClient, device)
		publishState(mqttClient, device)
	}

	log.Printf("publishing state for %d device(s) every %v", len(devices.Body), pollInterval)

	// Poll loop
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	doSync := func() {
		// Re-authenticate if token is about to expire
		tokensMu.Lock()
		if tokens.ExpiresOn < int(time.Now().Add(2*time.Minute).Unix()) {
			log.Println("token expiring soon, re-authenticating")
			tokens = authenticate(username, pass, tokensPath)
		}

		devices, err := GetDevices(defaultLocation.LocationID, tokens.AccessToken)
		tokensMu.Unlock()
		if err != nil {
			log.Printf("failed to get devices: %v", err)
			return
		}

		deviceStates.Update(devices.Body)

		for _, device := range devices.Body {
			publishState(mqttClient, device)
		}
	}

	for {
		select {
		case <-pubSync:
			doSync()

		case <-ticker.C:
			doSync()

		case sig := <-sigCh:
			log.Printf("received %v, shutting down", sig)

			// Mark all devices as unavailable
			for _, device := range devices.Body {
				prefix := mqttTopicPrefix(device.DeviceID)
				t := mqttClient.Publish(prefix+"/availability", 0, true, "offline")
				t.Wait()
			}

			mqttClient.Disconnect(1000)
			return
		}
	}
}
