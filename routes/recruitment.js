import { Router } from 'express';
import { requireApiKey } from '../middleware/auth.js';

const router = Router();

router.get('/', (req, res) => {
  res.status(200).json({ message: 'Recruitment API is working' });
});

export default router;
