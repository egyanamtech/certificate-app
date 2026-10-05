#!/bin/bash
PGBIN=$HOME/postgres/postgresql-16.15.0-x86_64-unknown-linux-gnu/bin
export LD_LIBRARY_PATH=$HOME/postgres/pgdebs/x/usr/lib:$HOME/postgres/pgdebs/x/usr/lib/x86_64-linux-gnu
[ -d "$HOME/postgres/pgdebs" ] && PGBIN=$HOME/postgres/pgdebs/x/usr/lib/postgresql/16/bin
if ! pg_isready -h localhost -p 5432 -U postgres >/dev/null 2>&1; then
  "$PGBIN"/pg_ctl -D "$HOME"/postgres/data -l "$HOME"/postgres/pg.log \
    -o "-p 5432 -c listen_addresses=localhost -c unix_socket_directories=$HOME/postgres -c dynamic_shared_memory_type=mmap" start
  echo "PostgreSQL started"
else
  echo "PostgreSQL already running"
fi