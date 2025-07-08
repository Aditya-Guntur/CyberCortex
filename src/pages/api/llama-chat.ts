import type { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { messages } = req.body;
  const formattedMessages = messages.map((m: any) => {
    if (m.imageUrl) {
      return {
        role: m.role,
        content: [
          { type: 'text', text: m.content },
          { type: 'image_url', image_url: { url: m.imageUrl } }
        ]
      };
    }
    return { role: m.role, content: m.content };
  });

  const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: 'meta-llama/llama-4-maverick:free',
      messages: formattedMessages
    })
  });
  const data = await response.json();
  res.status(200).json({ reply: data.choices?.[0]?.message?.content || 'No response from Llama.' });
} 