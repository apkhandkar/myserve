create table if not exists service_user (
  user_id varchar(50),
  joined timestamptz not null,
  auth_token uuid,
  decryption_key char(350) not null,
  verification_key char(44) not null,
  last_active_at timestamptz,
  primary key (user_id)
);

create table if not exists request_log (
  log_id uuid,
  client_address varchar(50) not null,
  request_headers json,
  path varchar(200) not null,
  timestamp timestamptz not null,
  primary key (log_id)
);