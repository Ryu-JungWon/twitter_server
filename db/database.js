import { config } from '../config.js';
import SQ from 'sequelize';

const { host, user, database, password } = config.db;

export const sequelize = new SQ.Sequelize(database, user, password, {
    host,
    dialect: 'mariadb',
    logging: false,
    timezone: "+09:00",
    port: '32631', // 포트 추가 !!!
});