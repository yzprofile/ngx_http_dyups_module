 #!/bin/bash

 for i in `seq 100`
 do
     echo 'curl -i -d "server 127.0.0.1:8088;" 127.0.0.1:8081/upstream/dyhost$i';
     curl -i -d "server 127.0.0.1:8088;" 127.0.0.1:8081/upstream/dyhost$i;echo "\n";
 done
