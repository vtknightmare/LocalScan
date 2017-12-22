--
-- PostgreSQL database dump
--

-- Dumped from database version 9.6.6
-- Dumped by pg_dump version 9.6.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: localscan; Type: DATABASE; Schema: -; Owner: postgres
--

CREATE DATABASE localscan WITH TEMPLATE = template0 ENCODING = 'UTF8' LC_COLLATE = 'en_US.UTF-8' LC_CTYPE = 'en_US.UTF-8';


ALTER DATABASE localscan OWNER TO postgres;

\connect localscan

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET search_path = public, pg_catalog;

--
-- Name: event_user_added(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION event_user_added() RETURNS trigger
    LANGUAGE plpgsql
    AS $$	 DECLARE BEGIN	 INSERT INTO logs(event_type, occur_time) VALUES('user_added', now());		RETURN NULL; 	END; 	$$;


ALTER FUNCTION public.event_user_added() OWNER TO postgres;

--
-- Name: start_occur(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION start_occur() RETURNS boolean
    LANGUAGE plpgsql
    AS $$	 DECLARE BEGIN	 INSERT INTO logs(event_type, occur_time) VALUES('process_started', now());		RETURN NULL; 	END; 	$$;


ALTER FUNCTION public.start_occur() OWNER TO postgres;

--
-- Name: windows_event_occur(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION windows_event_occur() RETURNS trigger
    LANGUAGE plpgsql
    AS $$	 DECLARE BEGIN	 INSERT INTO logs(event_type, occur_time) VALUES('windows_user_added', now());		RETURN NULL; 	END; 	$$;


ALTER FUNCTION public.windows_event_occur() OWNER TO postgres;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: broadcasts; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE broadcasts (
    sender_ip text NOT NULL,
    sender_mac text NOT NULL,
    data text
);


ALTER TABLE broadcasts OWNER TO postgres;

--
-- Name: logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE logs (
    event_type text NOT NULL,
    occur_time text NOT NULL
);


ALTER TABLE logs OWNER TO postgres;

--
-- Name: path_to_google; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE path_to_google (
    ip_adress text NOT NULL,
    is_private_ip text NOT NULL,
    geo_location text DEFAULT 'no_location_info'::text
);


ALTER TABLE path_to_google OWNER TO postgres;

--
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE users (
    ip_adress text NOT NULL,
    mac_adress text NOT NULL
);


ALTER TABLE users OWNER TO postgres;

--
-- Name: windows_users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE windows_users (
    ip_adress text NOT NULL,
    mac_adress text NOT NULL
);


ALTER TABLE windows_users OWNER TO postgres;

--
-- Data for Name: broadcasts; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: logs; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: path_to_google; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: windows_users; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Name: broadcasts broadcasts_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY broadcasts
    ADD CONSTRAINT broadcasts_pkey PRIMARY KEY (sender_ip, sender_mac);


--
-- Name: path_to_google path_to_google_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY path_to_google
    ADD CONSTRAINT path_to_google_pkey PRIMARY KEY (ip_adress);


--
-- Name: users unique_ip_adress; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY users
    ADD CONSTRAINT unique_ip_adress UNIQUE (ip_adress);


--
-- Name: users unique_mac_adress; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY users
    ADD CONSTRAINT unique_mac_adress UNIQUE (mac_adress);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY users
    ADD CONSTRAINT users_pkey PRIMARY KEY (ip_adress, mac_adress);


--
-- Name: windows_users windows_users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY windows_users
    ADD CONSTRAINT windows_users_pkey PRIMARY KEY (ip_adress, mac_adress);


--
-- Name: users trigger_user_added; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trigger_user_added AFTER INSERT ON users FOR EACH ROW EXECUTE PROCEDURE event_user_added();


--
-- Name: windows_users trigger_windows; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trigger_windows AFTER INSERT ON windows_users FOR EACH ROW EXECUTE PROCEDURE windows_event_occur();


--
-- PostgreSQL database dump complete
--

