/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package openwhisk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type initBodyRequest struct {
	Code   string                 `json:"code,omitempty"`
	Binary bool                   `json:"binary,omitempty"`
	Main   string                 `json:"main,omitempty"`
	Env    map[string]interface{} `json:"env,omitempty"`
}

type initRequest struct {
	Value initBodyRequest `json:"value,omitempty"`
}

func sendOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	buf := []byte("{\"ok\":true}\n")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(buf)))
	w.Write(buf)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (ap *ActionProxy) initHandler(w http.ResponseWriter, r *http.Request) {
	// --- Snapshots de début ---
	start := time.Now().UnixNano()
	energyStart, err := readEnergy()
	if err != nil {
		log.Printf("readEnergy start: %v", err)
	}
	// Pour /init le processus action n'est pas encore démarré,
	// donc cpuStart.ProcessTicks sera 0 — c'est attendu.
	cpuStart := readCPUSnapshot(0)

	if ap.initialized && !Debugging {
		msg := "Cannot initialize the action more than once."
		sendError(w, http.StatusForbidden, msg)
		log.Println(msg)
		return
	}

	if ap.compiler != "" {
		Debug("compiler: " + ap.compiler)
	}

	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		sendError(w, http.StatusBadRequest, fmt.Sprintf("%v", err))
		return
	}

	if len(body) < 1000 {
		Debug("init: decoding %s\n", string(body))
	}

	var request initRequest
	err = json.Unmarshal(body, &request)
	if err != nil {
		sendError(w, http.StatusBadRequest, fmt.Sprintf("Error unmarshaling request: %v", err))
		return
	}

	if request.Value.Code == "" {
		sendError(w, http.StatusForbidden, "Missing main/no code to execute.")
		return
	}

	ap.SetEnv(request.Value.Env)

	main := request.Value.Main
	if main == "" {
		main = "main"
	}

	var buf []byte
	if request.Value.Binary {
		Debug("it is binary code")
		buf, err = base64.StdEncoding.DecodeString(request.Value.Code)
		if err != nil {
			sendError(w, http.StatusBadRequest, "cannot decode the request: "+err.Error())
			return
		}
	} else {
		Debug("it is source code")
		buf = []byte(request.Value.Code)
	}

	_, err = ap.ExtractAndCompile(&buf, main)
	if err != nil {
		if os.Getenv("OW_LOG_INIT_ERROR") == "" {
			sendError(w, http.StatusBadGateway, err.Error())
		} else {
			ap.errFile.Write([]byte(err.Error() + "\n"))
			ap.outFile.Write([]byte(OutputGuard))
			ap.errFile.Write([]byte(OutputGuard))
			sendError(w, http.StatusBadGateway, "The action failed to generate or locate a binary. See logs for details.")
		}
		return
	}

	err = ap.StartLatestAction()
	if err != nil {
		if os.Getenv("OW_LOG_INIT_ERROR") == "" {
			sendError(w, http.StatusBadGateway, "cannot start action: "+err.Error())
		} else {
			ap.errFile.Write([]byte(err.Error() + "\n"))
			ap.outFile.Write([]byte(OutputGuard))
			ap.errFile.Write([]byte(OutputGuard))
			sendError(w, http.StatusBadGateway, "Cannot start action. Check logs for details.")
		}
		return
	}
	ap.initialized = true
	sendOK(w)

	meta := &RunMeta{PodName: os.Getenv("HOSTNAME")}
	ap.recordMetrics("/init", start, energyStart, cpuStart, meta)
}

// ExtractAndCompile decode the buffer and if a compiler is defined, compile it also
func (ap *ActionProxy) ExtractAndCompile(buf *[]byte, main string) (string, error) {

	file, err := ap.ExtractAction(buf, "src")
	if err != nil {
		return "", err
	}
	if file == "" {
		return "", fmt.Errorf("empty filename")
	}

	dir := filepath.Dir(file)
	parent := filepath.Dir(dir)
	srcDir := filepath.Join(parent, "src")
	binDir := filepath.Join(parent, "bin")
	binFile := filepath.Join(binDir, "exec")

	if ap.compiler == "" || isCompiled(file) {
		os.Rename(srcDir, binDir)
		return binFile, nil
	}

	Debug("compiling: %s main: %s", file, main)
	os.Mkdir(binDir, 0755)
	err = ap.CompileAction(main, srcDir, binDir)
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(binFile); os.IsNotExist(err) {
		return "", fmt.Errorf("cannot compile")
	}
	return binFile, nil
}