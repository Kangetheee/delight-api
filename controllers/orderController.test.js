import { placeOrder, verifyOrder } from './orderController.js'; // Adjust path accordingly
import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';
import orderModel from '../models/orderModel.js';
import userModel from '../models/userModel.js';
import { getAccessToken, registerIPNUrl } from './orderController.js';


const mock = new MockAdapter(axios);

// Mock access token response
const mockAccessTokenResponse = { token: 'mock_access_token' };
const mockIpnResponse = { ipn_status: 1 };
const mockOrderResponse = { status: '200', session_url: 'https://mock.url/session' };

beforeEach(() => {
    jest.clearAllMocks();
});

describe('PesaPal API Tests', () => {
    test('should fetch access token', async () => {
        mock.onPost('https://cybqa.pesapal.com/pesapalv3/api/Auth/RequestToken').reply(200, mockAccessTokenResponse);
        
        const token = await getAccessToken();
        expect(token).toBe(mockAccessTokenResponse.token);
    });

    test('should register IPN URL', async () => {
        mock.onPost('https://cybqa.pesapal.com/pesapalv3/api/URLSetup/RegisterIPN').reply(200, mockIpnResponse);
        
        const response = await registerIPNUrl('https://mock.url/ipn');
        expect(response).toBeUndefined(); // Assuming successful registration returns nothing
    });

    test('should place an order', async () => {
        const req = { body: { userId: 'user123', items: [], amount: 100, address: {} } };
        const res = { json: jest.fn() };

        // Mock order creation
        jest.spyOn(orderModel.prototype, 'save').mockResolvedValueOnce();

        // Mock user cart clearing
        jest.spyOn(userModel, 'findByIdAndUpdate').mockResolvedValueOnce();

        // Mock access token fetch
        mock.onPost('https://cybqa.pesapal.com/pesapalv3/api/Transactions/SubmitOrderRequest').reply(200, mockOrderResponse);

        await placeOrder(req, res);
        expect(res.json).toHaveBeenCalledWith({ success: true, session_url: mockOrderResponse.session_url });
    });

    test('should verify an order', async () => {
        const req = { body: { orderId: 'order123', success: 'true' } };
        const res = { json: jest.fn() };

        // Mock order update
        jest.spyOn(orderModel, 'findByIdAndUpdate').mockResolvedValueOnce();

        await verifyOrder(req, res);
        expect(res.json).toHaveBeenCalledWith({ success: true, message: "Paid" });
    });
});
