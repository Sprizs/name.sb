create user 'index3'@'localhost' identified by 'index3';
create database index3 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci SET ENGINE=InnoDB;
grant all privileges on index3.* to index3@localhost;