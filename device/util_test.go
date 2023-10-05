package device

import (
	"bytes"
	"fmt"
	"testing"
)

func Test_randomJunktWithSize(t *testing.T) {
	junk, err := randomJunkWithSize(30)
	fmt.Println(string(junk), len(junk), err)
}

func Test_appendJunk(t *testing.T) {
	t.Run("", func(t *testing.T) {
		s := "apple"
		buffer := bytes.NewBuffer([]byte(s))
		err := appendJunk(buffer, 30)
		if err != nil &&
			buffer.Len() != len(s)+30 {
			t.Errorf("appendWithJunk() size don't match")
		}
		read := make([]byte, 50)
		buffer.Read(read)
		fmt.Println(string(read))
	})
}
