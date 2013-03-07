for ((i=0;i<1000;i++)) do
    curl -d "server 127.0.0.1:8088;" 127.0.0.1:8081/upstream/dyhost$i
done

for ((i=0;i<1000;i++)) do
    curl -X DELETE 127.0.0.1:8081/upstream/dyhost$i
done
