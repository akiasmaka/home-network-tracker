package output

import (
	"encoding/json"
	"fmt"
	"net/http"

	ct "github.com/akiasmaka/home-network-tracker/go-loader/pkg/tracker"
)

type Server struct {
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Tracker *ct.ConnectionTracker
}

func enableCors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func (s *Server) Serve() {
	f := func(w http.ResponseWriter, r *http.Request) {
		enableCors(w)
		if r.Method != http.MethodGet {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		data := s.Tracker.Data.ToSilce()
		json.NewEncoder(w).Encode(data)
	}

	http.HandleFunc("/data", f)
	url := fmt.Sprintf("%s:%d", s.Addr, s.Port)
	fmt.Println("Server is running on ", url)
	if err := http.ListenAndServe(url, nil); err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
}
