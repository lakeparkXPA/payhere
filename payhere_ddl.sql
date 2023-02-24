CREATE DATABASE payhere;
use payhere;

DROP TABLE IF EXISTS `abook`;
DROP TABLE IF EXISTS `user`;

CREATE TABLE `user` (
	`user_id`	int PRIMARY KEY AUTO_INCREMENT	NOT NULL,
	`email`	varchar(255)	NULL,
	`password`	varchar(255)	NULL,
	`user_create_time`	datetime	NULL
);


CREATE TABLE `abook` (
	`abook_id`	int PRIMARY KEY AUTO_INCREMENT	NOT NULL,
	`user_id`	int	NOT NULL,
	`abook_time`	datetime	NULL,
	`amount`	int	NULL,
	`memo`	text	NULL
);
ALTER TABLE `abook` ADD CONSTRAINT `FK_user_TO_abook_1` FOREIGN KEY (
	`user_id`
)
REFERENCES `user` (
	`user_id`
);

