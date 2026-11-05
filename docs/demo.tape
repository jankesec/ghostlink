# Canonical recording for docs/demo.gif and docs/demo.mp4.
# Regenerate with: vhs docs/demo.tape

Output docs/demo.gif
Output docs/demo.mp4

Set Shell        zsh
Set FontFamily   "Menlo"
Set FontSize     14
Set Width        1200
Set Height       640
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
Type "export PS1='%F{cyan}security@lab%f %F{magenta}~/ghostlink%f %# '; clear"  Enter
Sleep 700ms
Show

Type "go run ./cmd/demo"
Sleep 250ms
Enter
Sleep 8s
