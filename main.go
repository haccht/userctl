package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/template"

	"github.com/Showmax/go-fqdn"
	"github.com/jessevdk/go-flags"
	"github.com/sethvargo/go-password/password"
	"github.com/tredoe/osutil/user/crypt"
	"github.com/tredoe/osutil/user/crypt/sha512_crypt"
	"golang.org/x/exp/slices"
	"gopkg.in/gomail.v2"
)

var (
	SMTP_HOST        string
	SMTP_PORT        string
	PERMITTED_DOMAIN string
)

var DefaultLoginDefs = map[string]string{"UID_MIN": "5000"}

var opts struct {
	AddCmd `command:"add"`
	ModCmd `command:"mod"`
	DelCmd `command:"del"`
}

type AddCmd struct {
	Uid       string                 `short:"u" long:"uid" value-name:"UID" description:"user ID of the new account"`
	Gid       string                 `short:"g" long:"gid" value-name:"GROUP" description:"name or ID of the primary group of the new account"`
	Groups    string                 `short:"G" long:"groups" value-name:"GROUPS" description:"list of supplementary groups of the new account"`
	Comment   string                 `short:"c" long:"comment" value-name:"COMMENT" description:"GECOS field of the new account"`
	Shell     string                 `short:"s" long:"shell" value-name:"SHELL" default:"/bin/bash" description:"login shell of the new account"`
	Password  string                 `short:"p" long:"password" value-name:"PASSWORD" description:"encrypted password of the new account"`
	LoginDefs map[string]string      `short:"K" long:"key" value-name:"KEY:VALUE" description:"override /etc/login.defs defaults"`
	Args      struct{ Email string } `positional-args:"yes" positional-arg-name:"EMAIL" required:"yes"`
}

func (sc *AddCmd) Execute(args []string) error {
	username, err := usernameFromMailAddr(sc.Args.Email)
	if err != nil {
		return err
	}

	params := []string{}

	if sc.Uid != "" {
		params = append(params, "-u", sc.Uid)
	}

	if sc.Gid != "" {
		params = append(params, "-g", sc.Gid)
	}

	if sc.Groups != "" {
		params = append(params, "-G", sc.Groups)
	}

	if sc.Comment == "" {
		sc.Comment = sc.Args.Email
	}

	if sc.Password == "" {
		sc.Password = password.MustGenerate(12, 4, 0, false, false)
	}

	hash, err := passwordSha512Crypt(sc.Password)
	if err != nil {
		return err
	}

	params = append(params, "-c", sc.Comment)
	params = append(params, "-s", sc.Shell)
	params = append(params, "-p", hash)

	loginDefs := DefaultLoginDefs
	for key, val := range sc.LoginDefs {
		loginDefs[key] = val
	}

	for key, val := range loginDefs {
		params = append(params, "-K", fmt.Sprintf("%s=%s", key, val))
	}

	params = append(params, "-m", "--badnames", username)

	useradd := exec.Command("useradd", params...)
	useradd.Stdout = os.Stdout
	useradd.Stderr = os.Stderr
	if err := useradd.Run(); err != nil {
		return fmt.Errorf("useradd failed: %s\n", err)
	}

	fmt.Printf("useradd: New account %s has successfully created.\n", username)

	passwd := exec.Command("passwd", "-e", username)
	passwd.Stdout = os.Stdout
	passwd.Stderr = os.Stderr
	if err := passwd.Run(); err != nil {
		return fmt.Errorf("passwd expiration failed: %s\n", err)
	}

	return sendUseraddMessage(sc.Args.Email, username, sc.Password)
}

func sendUseraddMessage(recipient, username, password string) error {
	const body = `
Hi {{.Username}},

We recieved a request to create your new {{.Hostname}} account.
Your account has been successfully created.

Here is your username and temporary password:
  username: {{.Username}}
  password: {{.Password}}

You are required to change your password immediately.
`

	hostname, err := fqdn.FqdnHostname()
	if err != nil {
		return err
	}

	tpl := template.Must(template.New("mail").Parse(body))
	bind := struct{ Hostname, Username, Password string }{hostname, username, password}

	var renderedBody bytes.Buffer
	if err := tpl.Execute(&renderedBody, bind); err != nil {
		return err
	}

	sender := fmt.Sprintf("admin@%s", hostname)
	return sendMessage(recipient, sender, "Your account has been created", renderedBody.String())
}

type ModCmd struct {
	Uid           string                 `short:"u" long:"uid" value-name:"UID" description:"new UID for the user account"`
	Gid           string                 `short:"g" long:"gid" value-name:"GROUP" description:"force use GROUP as new primary group"`
	Groups        string                 `short:"G" long:"groups" value-name:"GROUPS" description:"new list of supplementary GROUPS"`
	Append        bool                   `short:"a" long:"append" description:"append the user to the supplemental GROUPS mentioned by the -G option without removing the user from other groups"`
	Comment       string                 `short:"c" long:"comment" value-name:"COMMENT" description:"new value of the GECOS field"`
	Shell         string                 `short:"s" long:"shell" value-name:"SHELL" description:"new login shell for the user account"`
	Password      string                 `short:"p" long:"password" value-name:"PASSWORD" description:"use encrypted password for the new password"`
	ResetPassword bool                   `long:"reset-password" description:"reset password of the account"`
	Args          struct{ Email string } `positional-args:"yes" positional-arg-name:"EMAIL" required:"yes"`
}

func (sc *ModCmd) Execute(args []string) error {
	username, err := usernameFromMailAddr(sc.Args.Email)
	if err != nil {
		return err
	}

	params := []string{}

	if sc.Uid != "" {
		params = append(params, "-u", sc.Uid)
	}

	if sc.Gid != "" {
		params = append(params, "-g", sc.Gid)
	}

	if sc.Append {
		params = append(params, "-a")
	}

	if sc.Groups != "" {
		params = append(params, "-G", sc.Groups)
	}

	if sc.Comment != "" {
		params = append(params, "-c", sc.Comment)
	}

	if sc.Shell != "" {
		params = append(params, "-s", sc.Shell)
	}

	if sc.ResetPassword && sc.Password == "" {
		sc.Password = password.MustGenerate(12, 4, 0, false, false)
	}

	if sc.Password != "" {
		hash, err := passwordSha512Crypt(sc.Password)
		if err != nil {
			return err
		}

		params = append(params, "-p", hash)
	}

	params = append(params, username)

	usermod := exec.Command("usermod", params...)
	usermod.Stdout = os.Stdout
	usermod.Stderr = os.Stderr
	if err := usermod.Run(); err != nil {
		return fmt.Errorf("usermod failed: %s\n", err)
	}

	fmt.Printf("usermod: The account %s has successfully modified.\n", username)
	if sc.Password == "" {
		return nil
	}

	passwd := exec.Command("passwd", "-e", username)
	passwd.Stdout = os.Stdout
	passwd.Stderr = os.Stderr
	if err := passwd.Run(); err != nil {
		return fmt.Errorf("passwd expiration failed: %s\n", err)
	}

	return sendUsermodMessage(sc.Args.Email, username, sc.Password)
}

func sendUsermodMessage(recipient, username, password string) error {
	const body = `
Hi {{.Username}},

We recieved a request to reset your {{.Hostname}} password.
Your password has been successfully reset.

Here is your username and temporary password:
  username: {{.Username}}
  password: {{.Password}}

You are required to change your password immediately.
`

	hostname, err := fqdn.FqdnHostname()
	if err != nil {
		return err
	}

	tpl := template.Must(template.New("mail").Parse(body))
	bind := struct{ Hostname, Username, Password string }{hostname, username, password}

	var renderedBody bytes.Buffer
	if err := tpl.Execute(&renderedBody, bind); err != nil {
		return err
	}

	sender := fmt.Sprintf("admin@%s", hostname)
	return sendMessage(recipient, sender, "Your password has been reset", renderedBody.String())
}

type DelCmd struct {
	Args struct{ Email string } `positional-args:"yes" positional-arg-name:"EMAIL" required:"yes"`
}

func (sc *DelCmd) Execute(args []string) error {
	username, err := usernameFromMailAddr(sc.Args.Email)
	if err != nil {
		return err
	}

	params := []string{}
	params = append(params, "-r", "-f", username)

	userdel := exec.Command("userdel", params...)
	userdel.Stdout = os.Stdout
	userdel.Stderr = os.Stderr
	if err := userdel.Run(); err != nil {
		return fmt.Errorf("userdel failed: %s\n", err)
	}

	fmt.Printf("userdel: The account %s has successfully deleted.\n", username)
	return sendUserdelMessage(sc.Args.Email, username)
}

func sendUserdelMessage(recipient, username string) error {
	const body = `
Hi {{.Username}},

We recieved a request to delete your {{.Hostname}} account.
Your account has been successfully removed.
`

	hostname, err := fqdn.FqdnHostname()
	if err != nil {
		return err
	}

	tpl := template.Must(template.New("mail").Parse(body))
	bind := struct{ Hostname, Username string }{hostname, username}

	var renderedBody bytes.Buffer
	if err := tpl.Execute(&renderedBody, bind); err != nil {
		return err
	}

	sender := fmt.Sprintf("admin@%s", hostname)
	return sendMessage(recipient, sender, "Your account has been deleted", renderedBody.String())
}

func sendMessage(recipient, sender, subject, body string) error {
	msg := gomail.NewMessage()
	msg.SetHeader("To", recipient)
	msg.SetHeader("From", sender)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/plain", body)
	//fmt.Println(body)

	port, err := strconv.Atoi(SMTP_PORT)
	if err != nil {
		return fmt.Errorf("faild to parse smtp  port '%s': %s", SMTP_PORT, err)
	}

	mailer := gomail.Dialer{Host: SMTP_HOST, Port: port}
	if err := mailer.DialAndSend(msg); err != nil {
		return fmt.Errorf("failed to send message: %s", err)
	}
	return nil
}

func usernameFromMailAddr(mail string) (string, error) {
	tokens := strings.SplitN(mail, "@", 2)
	domains := strings.Split(PERMITTED_DOMAIN, ",")

	if len(tokens) < 2 || !slices.Contains(domains, tokens[1]) {
		return "", fmt.Errorf("Invalid email address: %s", mail)
	}
	return tokens[0], nil
}

func passwordSha512Crypt(password string) (string, error) {
	c := crypt.New(crypt.SHA512)
	s := sha512_crypt.GetSalt()

	saltString := string(s.GenerateWRounds(s.SaltLenMax, 0))
	return c.Generate([]byte(password), []byte(saltString))
}

func init() {
	if SMTP_HOST == "" {
		SMTP_HOST = "localhost"
	}

	if SMTP_PORT == "" {
		SMTP_PORT = "25"
	}

	if PERMITTED_DOMAIN == "" {
		PERMITTED_DOMAIN = "example.com"
	}
}

func main() {
	var parser = flags.NewParser(&opts, flags.Default)
	if _, err := parser.Parse(); err != nil {
		if fe, ok := err.(*flags.Error); ok && fe.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}
}
