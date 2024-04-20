package com.lovindata
package conf

import cats.effect.IO
import com.comcast.ip4s.IpLiteralSyntax
import com.comcast.ip4s.Port
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.server.middleware.{Logger => LoggerMiddleware}
import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.slf4j.Slf4jLogger
import org.typelevel.log4cats.syntax.LoggerInterpolator
import sttp.tapir.server.http4s.Http4sServerInterpreter
import sttp.tapir.swagger.bundle.SwaggerInterpreter

case class ApiConf()(implicit envConf: EnvConf, logger: Logger[IO] = Slf4jLogger.getLogger) {
  def setup: IO[Unit] = for {
    port            <- IO.fromOption(Port.fromInt(envConf.backendPort))(
                         new Throwable(s"Not processable port number ${envConf.backendPort}."))
    loggerMiddleware = LoggerMiddleware.httpRoutes(
                         logHeaders = true,
                         logBody = true,
                         redactHeadersWhen = _ => !envConf.backendDevMode,
                         logAction = Some((msg: String) => info"$msg")
                       )(_)
    _               <- EmberServerBuilder
                         .default[IO]
                         .withHost(ipv4"0.0.0.0")                          // Accept connections from any available network interface
                         .withPort(port)                                   // On port 8080
                         .withHttpApp(loggerMiddleware(allRts).orNotFound) // Link all routes to the backend server
                         .build
                         .use(_ => IO.never)
                         .start
                         .void
  } yield ()

  private val docsEpt = // Merge all endpoints as a fully usable OpenAPI doc
    SwaggerInterpreter().fromEndpoints[IO](List.empty, "Backend – TARP Stack ⛺", "1.0")
  private val allRts  = // Serve the OpenAPI doc & all the other routes
    Http4sServerInterpreter[IO]().toRoutes(docsEpt)
}

object ApiConf { implicit val impl: ApiConf = ApiConf() }
