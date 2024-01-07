-- schema of clients
create table if not exists oauth2_registered_client
(
    id                            varchar(100)  not null,
    client_id                     varchar(100)  not null,
    client_id_issued_at           timestamp          default current_timestamp not null,
    client_secret                 varchar(200)       default null,
    client_secret_expires_at      timestamp     null default null,
    client_name                   varchar(200)  not null,
    client_authentication_methods varchar(1000) not null,
    authorization_grant_types     varchar(1000) not null,
    redirect_uris                 varchar(1000)      default null,
    post_logout_redirect_uris     varchar(1000)      default null,
    scopes                        varchar(1000) not null,
    client_settings               varchar(2000) not null,
    token_settings                varchar(2000) not null,
    primary key (id)
);

-- schema of users
create table if not exists users
(
    username varchar(200) not null primary key,
    password varchar(500) not null,
    enabled  boolean      not null
);
create table if not exists authorities
(
    username  varchar(200) not null,
    authority varchar(50)  not null,
    constraint fk_authorities_users foreign key (username) references users (username),
    constraint username_authority unique (username, authority)
);

-- schema of authorization
create table if not exists oauth2_authorization_consent
(
    registered_client_id varchar(100)  not null,
    principal_name       varchar(200)  not null,
    authorities          varchar(1000) not null,
    primary key (registered_client_id, principal_name)
);
CREATE TABLE if not exists oauth2_authorization
(
    id                            varchar(100) NOT NULL,
    registered_client_id          varchar(100) NOT NULL,
    principal_name                varchar(200) NOT NULL,
    authorization_grant_type      varchar(100) NOT NULL,
    authorized_scopes             varchar(1000)     DEFAULT NULL,
    attributes                    blob              DEFAULT NULL,
    state                         varchar(500)      DEFAULT NULL,
    authorization_code_value      blob              DEFAULT NULL,
    authorization_code_issued_at  timestamp    null DEFAULT NULL,
    authorization_code_expires_at timestamp    null DEFAULT NULL,
    authorization_code_metadata   blob              DEFAULT NULL,
    access_token_value            blob              DEFAULT NULL,
    access_token_issued_at        timestamp    null DEFAULT NULL,
    access_token_expires_at       timestamp    null DEFAULT NULL,
    access_token_metadata         blob              DEFAULT NULL,
    access_token_type             varchar(100)      DEFAULT NULL,
    access_token_scopes           varchar(1000)     DEFAULT NULL,
    oidc_id_token_value           blob              DEFAULT NULL,
    oidc_id_token_issued_at       timestamp    null DEFAULT NULL,
    oidc_id_token_expires_at      timestamp    null DEFAULT NULL,
    oidc_id_token_metadata        blob              DEFAULT NULL,
    refresh_token_value           blob              DEFAULT NULL,
    refresh_token_issued_at       timestamp    null DEFAULT NULL,
    refresh_token_expires_at      timestamp    null DEFAULT NULL,
    refresh_token_metadata        blob              DEFAULT NULL,
    user_code_value               blob              DEFAULT NULL,
    user_code_issued_at           timestamp    null DEFAULT NULL,
    user_code_expires_at          timestamp    null DEFAULT NULL,
    user_code_metadata            blob              DEFAULT NULL,
    device_code_value             blob              DEFAULT NULL,
    device_code_issued_at         timestamp    null DEFAULT NULL,
    device_code_expires_at        timestamp    null DEFAULT NULL,
    device_code_metadata          blob              DEFAULT NULL,
    PRIMARY KEY (id)
);

-- schema of session
create table if not exists SPRING_SESSION
(
    primary_id            character(36) primary key not null,
    session_id            character(36)             not null,
    creation_time         bigint                    not null,
    last_access_time      bigint                    not null,
    max_inactive_interval integer                   not null,
    expiry_time           bigint                    not null,
    principal_name        character varying(100)
);
-- need to do when first execute these sql but undo when index has been created
# create unique index spring_session_ix1 on SPRING_SESSION (session_id) using btree;
# create index spring_session_ix2 on SPRING_SESSION (expiry_time) using btree;
# create index spring_session_ix3 on SPRING_SESSION (principal_name) using btree;
create table if not exists SPRING_SESSION_ATTRIBUTES
(
    session_primary_id character(36)          not null,
    attribute_name     character varying(200) not null,
    attribute_bytes    blob                   not null,
    constraint primary key (session_primary_id, attribute_name),
    constraint foreign key (session_primary_id) references SPRING_SESSION (primary_id) match simple on update no action on delete cascade
);

