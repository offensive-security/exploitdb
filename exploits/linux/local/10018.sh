while : ; do
   { echo y ; sleep 1 ; } | { while read ; do echo z$REPLY; done ; } &
   PID=$!
   OUT=$(ps -efl | grep 'sleep 1' | grep -v grep |
        { read PID REST ; echo $PID; } )
   OUT="${OUT%% *}"
   DELAY=$((RANDOM * 1000 / 32768))
   usleep $((DELAY * 1000 + RANDOM % 1000 ))
   echo n > /proc/$OUT/fd/1                 # Trigger defect
done