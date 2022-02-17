import config from 'config';
import { authHeader, handleResponse } from '@/_helpers';

export const userService = {
    getAll
};

function getAll() {
    const requestOptions = { method: 'GET', headers: authHeader() };
    console.log(`getAll headers: ${JSON.stringify(requestOptions)}`);
    return fetch(`${config.apiUrl}/users`, requestOptions).then(handleResponse);
}