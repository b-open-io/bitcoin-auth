import { getAuthToken } from 'bitcoin-auth';
import { PrivateKey } from '@bsv/sdk';

async function testGetToken() {
  try {
    console.log('Attempting to generate private key...');
    const privateKey = PrivateKey.fromRandom();
    const privateKeyWif = privateKey.toWif();
    console.log('Private key WIF:', privateKeyWif);

    const requestPath = '/api/test';
    const body = JSON.stringify({ message: 'hello world' });

    console.log('Attempting to get auth token...');
    const token = getAuthToken({ privateKeyWif, requestPath, body });
    console.log('Generated token:', token);
  } catch (error) {
    console.error('Error during getAuthToken test:');
    // Log the full error object, including stack if available
    if (error instanceof Error) {
      console.error('Message:', error.message);
      console.error('Stack:', error.stack);
    } else {
      console.error(error);
    }
  }
}

testGetToken(); 