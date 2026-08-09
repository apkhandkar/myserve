create table if not exists service_user (
  user_id varchar(50),
  joined timestamptz not null,
  auth_token uuid,
  encryption_key char(350) not null,
  verification_key char(44) not null,
  last_active_at timestamptz,
  primary key (user_id)
);

create table if not exists user_messages (
  message_id uuid,
  from_user user_id varchar(50),
  to_user user_id varchar(50),
  message_timestamp timestamptz not null,
  message_payload text not null,
  encrypted_symmetric_key char(344) not null,
  authentication_tag char(24) not null,
  nonce char(16) not null,
  foreign key from_user references service_user(user_id),
  foreign key to_user references service_user(user_id),
  primary key(message_id)
);

create table if not exists request_log (
  log_id uuid,
  client_address varchar(50) not null,
  request_headers json,
  path varchar(200) not null,
  timestamp timestamptz not null,
  primary key (log_id)
);