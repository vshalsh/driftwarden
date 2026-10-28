import axios from 'axios';

export const billing = axios.create({ baseURL: process.env.BILLING_URL });
