import microsoftbotframework.runcelery
from microsoftbotframework import MsBot
from tasks import *

bot = MsBot(__name__, verify_jwt_signature=False)
bot.add_process(respond_to_conversation_update)
bot.add_process(echo_response_async) # Only uncomment if a celery backend is configured
bot.add_process(echo_response)
bot.run(debug=True)