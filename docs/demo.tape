# Canonical recording for docs/demo.gif and docs/demo.mp4.
# Regenerate with: vhs docs/demo.tape

Output docs/demo.gif
Output docs/demo.mp4

Set Shell        zsh
Set FontFamily   "Menlo"
Set FontSize     14
Set Width        1200
Set Height       720
Set Padding      20
Set Margin       0
Set MarginFill   "#000000"
Set WindowBar    Colorful
Set BorderRadius 10
Set LineHeight   1.25
Set CursorBlink  true
Set TypingSpeed  28ms
Set PlaybackSpeed 1.0
Set Theme        { "name": "Termius Pro", "background": "#000000", "foreground": "#ffffff", "cursor": "#9aedfe", "cursorAccent": "#000000", "selection": "#2e3349", "black": "#000000", "red": "#ff5c57", "green": "#5af78e", "yellow": "#f3f99d", "blue": "#57c7ff", "magenta": "#ff6ac1", "cyan": "#9aedfe", "white": "#f1f1f0", "brightBlack": "#686868", "brightRed": "#ff5c57", "brightGreen": "#5af78e", "brightYellow": "#f3f99d", "brightBlue": "#57c7ff", "brightMagenta": "#ff6ac1", "brightCyan": "#9aedfe", "brightWhite": "#f1f1f0" }

Hide
Type "export PS1='%F{cyan}security@lab%f %F{magenta}~/ghostlink%f %# '; mkdir -p .demo/output; find .demo -mindepth 1 -delete; mkdir -p .demo/output; make build VERSION=v1.2.2 >/dev/null; clear"  Enter
Sleep 700ms
Show

Type "printf '%s' 'authorized loopback telemetry record' > .demo/input.txt"
Enter
Type "shasum -a 256 .demo/input.txt"
Enter
Sleep 2s

Type "addr=127.0.0.1:18080; key=demo-only-key"
Enter
Type "./bin/ghostlink-server -channel http -addr $addr -key $key -output-dir .demo/output </dev/null >.demo/server.log 2>&1 & server_pid=$!"
Sleep 250ms
Enter
Sleep 2s

Type "./bin/ghostlink-client -channel http -addr $addr -key $key -send-file .demo/input.txt"
Sleep 250ms
Enter
Sleep 3s

Type "sed -n '1,12p' .demo/server.log"
Enter
Sleep 3s

Type "cmp .demo/input.txt .demo/output/input.txt_1 && echo 'PASS  received bytes exactly match the sender'"
Sleep 250ms
Enter
Type "shasum -a 256 .demo/output/input.txt_1"
Enter
Sleep 4s

Type "kill $server_pid"
Enter
Sleep 1s
Hide
Type "wait $server_pid 2>/dev/null; find .demo -mindepth 1 -delete; rmdir .demo; clear"
Enter
