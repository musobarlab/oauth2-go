package security

// Interface interface
type Interface interface {
	Encrypt(text string) (string, error)
	Decrypt(encryptedText string) (string, error)
}
