#!/bin/bash

echo "Starting sequential stress test: 10,000 connections sending 'ping' to localhost:10007"
time for i in {1..10000}; do
  echo "ping" | nc -N localhost 10007 > /dev/null
done
echo "Test complete."
