import { Controller, Get, Param } from '@nestjs/common';
import { ChatService } from './chat.service';

@Controller('chat')
export class ChatController {
  constructor(private chatService: ChatService) {}

  @Get('get-my-chats/:id')
  async getMyChats(@Param('id') id: string) {
    return this.chatService.getMyChats(id);
  }
}
