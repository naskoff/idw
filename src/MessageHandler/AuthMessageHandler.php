<?php

namespace App\MessageHandler;

use App\Message\AuthMessage;
use Symfony\Component\Messenger\Handler\MessageHandlerInterface;

final class AuthMessageHandler implements MessageHandlerInterface
{
    public function __invoke(AuthMessage $message)
    {
        // do something with your message
    }
}
