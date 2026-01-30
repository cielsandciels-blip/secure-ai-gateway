package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// ログデータ構造体
type LogEntry struct {
	Time    string
	Status  string
	Message string
}

// チャットリクエスト構造体
type ChatRequest struct {
	Message string `json:"message"`
}

func main() {
	godotenv.Load()

	// === ルーティング（3つの入り口を設定） ===
	http.HandleFunc("/chat", handleChat)   // 1. 裏側の処理 (API)
	http.HandleFunc("/admin", handleAdmin) // 2. 管理画面 (ダッシュボード)
	http.HandleFunc("/", handleIndex)      // 3. 社員用チャット画面 (トップページ)

	fmt.Println("=== 🛡️ Secure AI Gateway 起動完了 ===")
	fmt.Println("👨‍💼 社員用チャット: http://localhost:8080/")
	fmt.Println("📊 管理ダッシュボード: http://localhost:8080/admin")
	
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

// ---------------------------------------------------------
// 1. 社員Aが使うチャット画面 (HTML/Frontend)
// ---------------------------------------------------------
func handleIndex(w http.ResponseWriter, r *http.Request) {
	// 管理画面(/admin)へのアクセスが "/" に流れないようにする対策
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<meta charset="UTF-8">
		<title>社内AIポータル</title>
		<style>
			body { max-width: 800px; margin: 0 auto; padding: 20px; font-family: 'Segoe UI', sans-serif; background: #f0f2f5; }
			.chat-container { background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
			.header { background: #4a5568; color: white; padding: 15px; text-align: center; font-weight: bold; }
			#chat-box { height: 400px; overflow-y: scroll; padding: 20px; border-bottom: 1px solid #eee; background: #fff; }
			.input-area { padding: 20px; display: flex; gap: 10px; background: #f8f9fa; }
			textarea { flex: 1; height: 50px; padding: 10px; border: 1px solid #ddd; border-radius: 5px; resize: none; }
			button { background: #3182ce; color: white; border: none; padding: 0 20px; border-radius: 5px; cursor: pointer; font-weight: bold; }
			button:hover { background: #2c5282; }
			
			/* メッセージのスタイル */
			.message { margin-bottom: 15px; padding: 10px 15px; border-radius: 10px; max-width: 80%; line-height: 1.4; }
			.user-msg { background: #e3f2fd; color: #0d47a1; margin-left: auto; text-align: left; }
			.ai-msg { background: #f1f3f4; color: #333; margin-right: auto; }
			.error-msg { background: #ffebee; color: #c62828; margin-right: auto; border: 1px solid #ffcdd2; }
			.timestamp { font-size: 0.7em; color: #888; margin-top: 5px; text-align: right; }
		</style>
	</head>
	<body>
		<div class="chat-container">
			<div class="header">社内専用セキュアAIチャット</div>
			<div id="chat-box">
				<div class="message ai-msg">こんにちは。業務に関する質問があればどうぞ。<br><small style="color:red">※機密情報の入力は禁止されています。</small></div>
			</div>
			<div class="input-area">
				<textarea id="msg" placeholder="ここにメッセージを入力... (例: コードのバグを見つけて)"></textarea>
				<button onclick="send()">送信</button>
			</div>
		</div>

		<script>
			async function send() {
				const input = document.getElementById('msg');
				const msg = input.value;
				if(!msg.trim()) return;
				
				// 自分のメッセージを表示
				const box = document.getElementById('chat-box');
				addMessage(msg, 'user-msg');
				input.value = '';

				// サーバーに送信
				try {
					const res = await fetch('/chat', {
						method: 'POST',
						body: JSON.stringify({ message: msg })
					});
					const text = await res.text();
					
					if (res.status === 403) {
						addMessage('⚠️ ' + text, 'error-msg'); // ブロックされた時
					} else {
						addMessage(text, 'ai-msg'); // 正常な時
					}
				} catch (e) {
					addMessage('エラーが発生しました', 'error-msg');
				}
			}

			function addMessage(text, className) {
				const box = document.getElementById('chat-box');
				const div = document.createElement('div');
				div.className = 'message ' + className;
				div.innerHTML = text.replace(/\n/g, '<br>');
				box.appendChild(div);
				box.scrollTop = box.scrollHeight;
			}
		</script>
	</body>
	</html>`
	fmt.Fprint(w, html)
}

// ---------------------------------------------------------
// 2. チャット処理（多重防御システム）
// ---------------------------------------------------------
func handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// === セキュリティ・チェック ===

	// A. 禁止用語
	forbiddenWords := []string{"社外秘", "機密", "パスワード", "password", "SECRET", "年収"}
	for _, word := range forbiddenWords {
		if strings.Contains(req.Message, word) {
			blockWithLog(w, req.Message, "禁止用語: "+word)
			return
		}
	}

	// B. 個人情報
	emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	if emailPattern.MatchString(req.Message) {
		blockWithLog(w, req.Message, "検知: メールアドレス流出")
		return
	}

	// C. シークレットスキャン (APIキー)
	googleKeyPattern := regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`)
	awsKeyPattern := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	if googleKeyPattern.MatchString(req.Message) || awsKeyPattern.MatchString(req.Message) {
		blockWithLog(w, req.Message, "検知: APIキー流出")
		return
	}

	// D. ソースコード検知
	codePattern := regexp.MustCompile(`(func|class|import|package|def|public|private)\s+`)
	if codePattern.MatchString(req.Message) {
		blockWithLog(w, req.Message, "検知: ソースコード送信")
		return
	}

	// === ✅ 合格 ===
	writeAuditLog("ALLOW", req.Message)
	aiReply := askGeminiMock(req.Message)
	fmt.Fprintf(w, "%s", aiReply)
}

func blockWithLog(w http.ResponseWriter, message, reason string) {
	writeAuditLog("BLOCK", message+" ("+reason+")")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "【遮断】セキュリティ違反です。\n理由: %s", reason)
}

func askGeminiMock(message string) string {
	return fmt.Sprintf("【AI】(模擬応答)\n確認しました。「%s」ですね。\nこの内容はポリシーに準拠しています。", message)
}

// ---------------------------------------------------------
// 3. 管理画面（ダッシュボード）
// ---------------------------------------------------------
func handleAdmin(w http.ResponseWriter, r *http.Request) {
	content, err := os.ReadFile("audit_log.txt")
	if err != nil {
		// ファイルがない場合もエラーにせず空データを表示
		content = []byte("") 
	}

	lines := strings.Split(string(content), "\n")
	var logs []LogEntry
	blockCount := 0
	allowCount := 0
	keywordMap := make(map[string]int)

	for _, line := range lines {
		if line == "" || !strings.Contains(line, "]") { continue }

		status := "ALLOW"
		if strings.Contains(line, "[BLOCK]") {
			status = "BLOCK"
			blockCount++
			
			start := strings.LastIndex(line, "(")
			end := strings.LastIndex(line, ")")
			if start != -1 && end != -1 && end > start {
				reason := line[start+1 : end]
				reason = strings.Replace(reason, "検知: ", "", 1)
				reason = strings.Replace(reason, "禁止用語: ", "", 1)
				keywordMap[reason]++
			} else {
				keywordMap["その他"]++
			}
		} else {
			allowCount++
		}

		timePart := ""
		if len(line) > 20 { timePart = line[1:20] }
		messagePart := ""
		if idx := strings.LastIndex(line, "内容: "); idx != -1 {
			messagePart = line[idx+7:]
		}
		logs = append(logs, LogEntry{Time: timePart, Status: status, Message: messagePart})
	}

	data := struct {
		Logs    []LogEntry
		Total   int
		Block   int
		Allow   int
		Ranking map[string]int
	}{
		Logs: logs, Total: blockCount + allowCount, Block: blockCount, Allow: allowCount, Ranking: keywordMap,
	}

	// シンプルで綺麗なダッシュボード
	tmpl := `
	<!DOCTYPE html>
	<html>
	<head>
		<meta charset="UTF-8">
		<title>Admin Dashboard</title>
		<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
		<style>
			body { font-family: sans-serif; margin: 0; background: #f4f6f8; }
			.navbar { background: #343a40; color: white; padding: 15px 20px; font-weight: bold; font-size: 1.2em; }
			.container { max-width: 1200px; margin: 20px auto; padding: 0 20px; }
			.grid { display: grid; grid-template-columns: 3fr 1fr; gap: 20px; margin-bottom: 20px; }
			.card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
			.stats-row { display: flex; gap: 20px; margin-bottom: 20px; }
			.stat-box { flex: 1; padding: 20px; color: white; border-radius: 8px; text-align: center; }
			.bg-blue { background: #4dabf7; } .bg-red { background: #ff6b6b; } .bg-green { background: #51cf66; }
			.num { font-size: 2em; font-weight: bold; }
			table { width: 100%; border-collapse: collapse; margin-top: 10px; }
			th, td { padding: 10px; border-bottom: 1px solid #eee; text-align: left; font-size: 0.9em; }
			.BLOCK { color: #e03131; font-weight: bold; } .ALLOW { color: #2f9e44; font-weight: bold; }
		</style>
	</head>
	<body>
		<div class="navbar">Secure AI Gateway 管理画面</div>
		<div class="container">
			<div class="stats-row">
				<div class="stat-box bg-blue"><div>総アクセス</div><div class="num">{{.Total}}</div></div>
				<div class="stat-box bg-red"><div>ブロック</div><div class="num">{{.Block}}</div></div>
				<div class="stat-box bg-green"><div>許可</div><div class="num">{{.Allow}}</div></div>
			</div>
			<div class="grid">
				<div class="card">
					<h3>最新のログ</h3>
					<table>
						<tr><th>日時</th><th>判定</th><th>内容</th></tr>
						{{range .Logs}}
						<tr><td>{{.Time}}</td><td class="{{.Status}}">{{.Status}}</td><td>{{.Message}}</td></tr>
						{{end}}
					</table>
				</div>
				<div class="card">
					<h3>検知ランキング</h3>
					<ul>
					{{range $key, $val := .Ranking}}
						<li><b>{{$key}}</b>: {{$val}}回</li>
					{{end}}
					</ul>
					<canvas id="chart"></canvas>
				</div>
			</div>
		</div>
		<script>
			new Chart(document.getElementById('chart'), {
				type: 'doughnut',
				data: { labels: ['ブロック', '許可'], datasets: [{ data: [{{.Block}}, {{.Allow}}], backgroundColor: ['#ff6b6b', '#51cf66'] }] }
			});
		</script>
	</body>
	</html>`
	template.Must(template.New("admin").Parse(tmpl)).Execute(w, data)
}

func writeAuditLog(status, message string) {
	file, err := os.OpenFile("audit_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil { return }
	defer file.Close()
	file.WriteString(fmt.Sprintf("[%s] [%s] 内容: %s\n", time.Now().Format("2006-01-02 15:04:05"), status, message))
}