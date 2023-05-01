package sh_run_pipe

import (
	"bufio"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
)

var f_content []string

func Load(in_file string) error {
	if f_content != nil {
		f_content = f_content[:0] // clear slice and keep the same capacity
	}

	readFile, err := os.Open(in_file)
	if err != nil {
		log.Println("ERROR:", err)
		return err
	}
	defer readFile.Close()

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		f_content = append(f_content, fileScanner.Text())
	}

	return nil
}

func Exact(pattern string) Text {
	var result Text

	for _, line := range f_content {
		if strings.Trim(line, " \t") == pattern {
			result = append(result, line)
		}
	}
	return result
}

func Include(pattern string) Text {
	var result Text

	for _, line := range f_content {
		if strings.Contains(line, pattern) {
			result = append(result, line)
		}
	}
	return result
}

func Prefix(pattern string) Text {
	var result Text

	for _, line := range f_content {
		if strings.HasPrefix(line, pattern) {
			result = append(result, line)
		}
	}
	return result
}

func getLineIdentation(line string) (uint, error) {
	var result uint
	len := len(line)

	for i := 0; i < len; i++ {
		if line[i] == ' ' {
			result++
		} else {
			break
		}
	}

	return result, nil
}

func makeIdentation(ident_len uint) string {
	result := ""
	var i uint
	for i = 0; i < ident_len; i++ {
		result += " "
	}

	return result
}

func section(pattern string, exact bool) Text {
	var result Text
	ident := ""

	for _, line := range f_content {
		// --- search for pattern
		if ((exact == false) && strings.Contains(line, pattern)) || ((exact == true) && (strings.Trim(line, " \t") == pattern)) {
			ident_len, err := getLineIdentation(line)
			if err != nil {
				return nil
			}

			ident = makeIdentation(ident_len + 1)

			result = append(result, line)
			continue
		}
		if len(ident) > 0 {
			// -- collect lines with identation
			if strings.HasPrefix(line, ident) {
				result = append(result, line)
			} else {
				ident = ""
			}
		}
	}

	return result
}

func Section(pattern string) Text {
	return section(pattern, false)
}

func SectionExact(pattern string) Text {
	return section(pattern, true)
}

func (t Text) Exclude(pattern string) Text {
	var result Text

	for _, line := range t {
		if strings.Contains(line, pattern) {
		} else {
			result = append(result, line)
		}
	}

	return result
}

func (t Text) Include(pattern string) Text {
	var result Text

	for _, line := range t {
		if strings.Contains(line, pattern) {
			result = append(result, line)
		}
	}

	return result
}

func (t Text) Len() uint {
	return uint(len([]string(t)))
}

func (t Text) Get(idx uint) (string, error) {
	if t.Len() < idx {
		error_message := "Index " + strconv.Itoa(int(idx)) + " requested from text higher than amount of lines in text (" + strconv.Itoa(int(t.Len())) + ")"
		log.Printf("ERROR: %s\n", error_message)
		return "", errors.New(error_message)
	}
	return []string(t)[idx], nil
}
