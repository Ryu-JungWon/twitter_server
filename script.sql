use kdt;

create table users (
	id int auto_increment primary key,
    username varchar(50) unique not null,
    password varchar(50) not null,
    name varchar(20) not null,
    email varchar(50) not null,
    url varchar(200)
);

select * from users;

create table tweets (
	id int auto_increment primary key,
    userId int not null,
    createdAt datetime default now(),
    text varchar(2000) not null,
    foreign key(userId) references users(id)
);

select * from tweets;