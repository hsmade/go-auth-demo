#!/bin/bash
curl http://localhost:8000/token/create -d '{"username":"user1","password":"password1"}' -c cookies --fail || echo fail
curl http://localhost:8000/test -b cookies -c cookies --fail || echo fail
sleep 6
curl http://localhost:8000/test -b cookies -c cookies --fail 2>/dev/null && echo fail
curl http://localhost:8000/token/create -d '{"username":"user1","password":"password1"}' -c cookies --fail || echo fail
curl http://localhost:8000/token/refresh -d '{"username":"user1","password":"password1"}' -c cookies -b cookies --fail || echo fail
curl http://localhost:8000/test -b cookies -c cookies --fail || echo fail
