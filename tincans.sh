#!/bin/sh
# Tin Cans without Node: needs only curl, openssl and xxd.
# Usage: tincans.sh '<link>' join | send '<text>' | read
# Protocol: link = ORIGIN/#SECRET (SECRET is 22 base64url chars, kept local).
#   channel = first 32 hex of sha256("tincans/v1/channel:"+SECRET)
#   enc key = sha256("tincans/v1/enc:"+SECRET), mac key = hex(sha256("tincans/v1/mac:"+SECRET)) as ASCII
#   wire = hex(iv16) + hex(AES-256-CTR(envelope)) + hex(HMAC-SHA-256(mac key, iv+ct hex)), lowercase
#   envelope = {"v":1,"seat":N,"name":..,"t":ms,"kind":"text","body":..}
# Every request carries header x-tincans-seat: <32 hex token>; the token is
# kept in $TINCANS_HOME/<channel>.seat. POST ORIGIN/c/<channel>/join gives the
# seat; POST /c/<channel>/messages sends the wire; GET /c/<channel>/messages?
# after=N&format=text lists "<seq> <from> <wire>" lines. The secret never
# leaves this machine. TINCANS_NAME sets your name (default: shell).
# On a shared machine, beware: the derived keys (openssl -K, -hmac) and the
# seat token (curl -H) are passed as command arguments, so other users can see
# them in the process list (ps) while the script runs. Use the Node client there.
set -eu
umask 077
link=$(printf %s "${1:-}" | tr -d '"'"'"'[:space:]`')
cmd=${2:-}
case $link in
  http://*/\#??????????????????????|https://*/\#??????????????????????) ;;
  http://*\#??????????????????????|https://*\#??????????????????????) link=${link%%#*}/#${link##*#} ;;
  *) echo "usage: tincans.sh '<link>' join|send '<text>'|read" >&2; exit 1 ;;
esac
origin=${link%%/#*}
secret=${link##*#}
home=${TINCANS_HOME:-$HOME/.tincans}
name=${TINCANS_NAME:-shell}
sha() { printf %s "$1" | openssl dgst -sha256 -r | cut -c1-64; }
chan=$(sha "tincans/v1/channel:$secret" | cut -c1-32)
enchex=$(sha "tincans/v1/enc:$secret")
mac=$(sha "tincans/v1/mac:$secret")
mkdir -p "$home"; chmod 700 "$home"
seatfile=$home/$chan.seat
api=$origin/c/$chan

join() {
  if [ -s "$seatfile" ]; then token=$(sed -n 1p "$seatfile"); else token=$(openssl rand -hex 16); fi
  resp=$(curl -s -X POST -H "x-tincans-seat: $token" "$api/join")
  seat=$(printf %s "$resp" | sed -n 's/.*"seat":\([0-9]*\).*/\1/p')
  [ -n "$seat" ] || { echo "join failed: $resp" >&2; exit 1; }
  printf '%s\n%s\n' "$token" "$seat" > "$seatfile"; chmod 600 "$seatfile"
  echo "joined as seat $seat"
}
need_seat() {
  [ -s "$seatfile" ] || { echo "not joined: run join first" >&2; exit 1; }
  token=$(sed -n 1p "$seatfile"); seat=$(sed -n 2p "$seatfile")
}

case $cmd in
  join) join ;;
  send)
    need_seat
    # JSON control-character escapes: tab, CR, then every other char below 0x20.
    esc=""
    for c in 1 2 3 4 5 6 7 8 11 12 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31; do
      ch=$(printf "\\$(printf %03o "$c")")
      esc="$esc -e s/$ch/\\\\u$(printf %04x "$c")/g"
    done
    tab=$(printf '\t'); cr=$(printf '\r')
    # shellcheck disable=SC2086
    body=$(printf %s "${3:-}" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e "s/$tab/\\\\t/g" -e "s/$cr/\\\\r/g" $esc | awk 'NR>1{printf "\\n"} {printf "%s",$0}')
    t=${TINCANS_TEST_T:-$(( $(date +%s) * 1000 ))}
    iv=${TINCANS_TEST_IV:-$(openssl rand -hex 16)}
    env=$(printf '{"v":1,"seat":%s,"name":"%s","t":%s,"kind":"text","body":"%s"}' "$seat" "$name" "$t" "$body")
    ct=$(printf %s "$env" | openssl enc -aes-256-ctr -K "$enchex" -iv "$iv" | xxd -p | tr -d '\n')
    tag=$(printf %s "$iv$ct" | openssl dgst -sha256 -hmac "$mac" -r | cut -c1-64)
    code=$(printf %s "$iv$ct$tag" | curl -s -o /dev/null -w '%{http_code}' -X POST -H "x-tincans-seat: $token" --data-binary @- "$api/messages")
    [ "$code" = 200 ] || { echo "send failed: HTTP $code" >&2; exit 1; }
    ;;
  read)
    need_seat
    bs=$(printf '\001')
    curl -s -H "x-tincans-seat: $token" "$api/messages?after=0&format=text" | while read -r seq from wire; do
      [ -n "$wire" ] || continue
      iv=$(printf %s "$wire" | cut -c1-32)
      want=$(printf %s "${wire%????????????????????????????????????????????????????????????????}" | openssl dgst -sha256 -hmac "$mac" -r | cut -c1-64)
      [ "$want" = "${wire#"${wire%????????????????????????????????????????????????????????????????}"}" ] || continue
      rest=${wire%????????????????????????????????????????????????????????????????}
      # Decrypted straight into a variable: the plaintext never touches disk.
      json=$(printf %s "${rest#"$iv"}" | xxd -r -p | openssl enc -d -aes-256-ctr -K "$enchex" -iv "$iv")
      n=$(printf %s "$json" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')
      b=$(printf %s "$json" | sed -e 's/.*"body":"//' -e 's/"}$//' | sed -e 's/\\\\/'"$bs"'/g' -e 's/\\n/\
/g' -e 's/\\t/	/g' -e 's/\\"/"/g' -e 's/'"$bs"'/\\/g')
      printf '[%s] %s: %s\n' "$seq" "$n" "$b"
    done
    ;;
  *) echo "usage: tincans.sh '<link>' join|send '<text>'|read" >&2; exit 1 ;;
esac
