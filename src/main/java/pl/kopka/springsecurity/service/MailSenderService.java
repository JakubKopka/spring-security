package pl.kopka.springsecurity.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import pl.kopka.springsecurity.model.AppUser;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

@Service
public class MailSenderService {

    Logger logger = LoggerFactory.getLogger(MailSenderService.class);

    @Value("${admin.verification.email}")
    private String adminMail;

    private final JavaMailSender javaMailSender;

    @Autowired
    public MailSenderService(JavaMailSender javaMailSender) {
        this.javaMailSender = javaMailSender;
    }

    public void sendMail(String to, String subject, String text, boolean isHtmlContent) throws MessagingException {
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, true);
        mimeMessageHelper.setTo(to);
        mimeMessageHelper.setSubject(subject);
        mimeMessageHelper.setText(text, isHtmlContent);
        javaMailSender.send(mimeMessage);
    }


    public void sendVerificationMailToUser(AppUser appUser, String url) {
        logger.info("Sending verification mail to user, e-mail: " + appUser.getMail());
        String mailContent = "Hello! This is your verification link: " + url;
        try {
            this.sendMail(appUser.getMail(), "Verify your account!", mailContent, false);
        } catch (MessagingException messagingException) {
            logger.error(messagingException.getMessage());
        }
    }

    public void sendVerificationMailToAdmin(AppUser appUser, String url) {
        logger.info("Sending verification mail to Admin");
        String mailContent = "Hello, Someone (" + appUser.getMail() + ") want to be ADMIN in your site. " +
                "If you accept this request, please click on this verification link: " + url;
        try {
            this.sendMail(adminMail, "Verify admin account request!", mailContent, false);
        } catch (MessagingException messagingException) {
            logger.error(messagingException.getMessage());
        }
    }
}
