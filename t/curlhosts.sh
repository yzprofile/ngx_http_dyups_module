for i in `seq 10000`
do
    echo "curl -i -H "Host" 127.0.0.1:8081/upstream/dyhost"$i;
    curl -i -H "Host: dyhost$i" 127.0.0.1:8080;echo "\n";
done
