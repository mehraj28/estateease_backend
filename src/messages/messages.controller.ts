import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { MessagesService } from './messages.service';
import { SendMessageDto } from './dto/send-message.dto';

@Controller('messages')
export class MessagesController {
  constructor(private messageService: MessagesService) {}

  @Post('send-message')
  async sendMessage(@Body() data: SendMessageDto) {
    return this.messageService.sendMessage(data);
  }

  //get all messages of a chat conversation id
  @Get('get-messages/:senderId/:receiverId')
  async getMessages(
    @Param('senderId') senderId: string,
    @Param('receiverId') receiverId: string,
  ) {
    return await this.messageService.getAllMessages([senderId, receiverId]);
  }

  //get all messages
  @Get('all/:id')
  async getAllMessages(@Param('id') id: string) {
    return await this.messageService.getAllUserMessages(id);
  }
}
